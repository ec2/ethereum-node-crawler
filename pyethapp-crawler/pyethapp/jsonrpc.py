import os
import inspect
from copy import deepcopy
from collections import Iterable

import ethereum.blocks
import ethereum.bloom as bloom
import ethereum.slogging as slogging
import gevent
import gevent.queue
import gevent.wsgi
import rlp
from decorator import decorator
from accounts import Account
from devp2p.service import BaseService
from ethereum import processblock
from ethereum.exceptions import InvalidTransaction
from ethereum.slogging import LogRecorder
from ethereum.transactions import Transaction
from ethereum.trie import Trie
from ethereum.utils import (
    big_endian_to_int, decode_hex, denoms, encode_hex, int_to_big_endian, is_numeric,
    is_string, int32, sha3, zpad,
)
from eth_protocol import ETHProtocol
from ipc_rpc import bind_unix_listener, serve
from tinyrpc.dispatch import public as public_
from tinyrpc.dispatch import RPCDispatcher
from tinyrpc.exc import BadRequestError, MethodNotFoundError
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol, JSONRPCInvalidParamsError
from tinyrpc.server.gevent import RPCServerGreenlets
from tinyrpc.transports import ServerTransport
from tinyrpc.transports.wsgi import WsgiServerTransport

logger = log = slogging.get_logger('jsonrpc')

# defaults
default_startgas = 500 * 1000
default_gasprice = 60 * denoms.shannon


def _fail_on_error_dispatch(self, request):
    method = self.get_method(request.method)
    # we found the method
    result = method(*request.args, **request.kwargs)
    return request.respond(result)


PROPAGATE_ERRORS = False
if PROPAGATE_ERRORS:
    RPCDispatcher._dispatch = _fail_on_error_dispatch


# route logging messages


class WSGIServerLogger(object):

    _log = slogging.get_logger('jsonrpc.wsgi')

    @classmethod
    def log(cls, msg):
        cls._log.debug(msg.strip())
    write = log

    @classmethod
    def log_error(cls, msg, *args):
        cls._log.error(msg % args)

gevent.wsgi.WSGIHandler.log_error = WSGIServerLogger.log_error


# hack to return the correct json rpc error code if the param count is wrong
# (see https://github.com/mbr/tinyrpc/issues/19)

public_methods = dict()


def public(f):
    public_methods[f.__name__] = inspect.getargspec(f)

    def new_f(*args, **kwargs):
        try:
            inspect.getcallargs(f, *args, **kwargs)
        except TypeError as t:
            raise JSONRPCInvalidParamsError(t)
        else:
            return f(*args, **kwargs)
    new_f.func_name = f.func_name
    new_f.func_doc = f.func_doc
    return public_(new_f)


class LoggingDispatcher(RPCDispatcher):

    """A dispatcher that logs every RPC method call."""

    def __init__(self):
        super(LoggingDispatcher, self).__init__()
        self.logger = log.debug

    def dispatch(self, request):
        try:
            if isinstance(request, Iterable):
                request_list = request
            else:
                request_list = [request]
            for req in request_list:
                self.logger('------------------------------')
                self.logger('RPC call', method=req.method, args_=req.args, kwargs=req.kwargs,
                            id=req.unique_id)
            response = super(LoggingDispatcher, self).dispatch(request)
            if isinstance(response, Iterable):
                response_list = response
            else:
                response_list = [response]
            for res in response_list:
                if hasattr(res, 'result'):
                    self.logger('RPC result', id=res.unique_id, result=res.result)
                else:
                    self.logger('RPC error', id=res.unique_id, error=res.error)
            return response
        except KeyError as e:
            log.error("Unknown/unhandled RPC method!", method=e.args[0])


class IPCDomainSocketTransport(ServerTransport):
    """tinyrpc ServerTransport implementation for unix domain sockets.
    """
    def __init__(self, sockpath=None, queue_class=gevent.queue.Queue):
        self.socket = bind_unix_listener(sockpath)
        self.messages = queue_class()
        self.replies = queue_class()

    def handle(self, socket, address):
        while True:
            try:
                msg = socket.recv(4096)
                if not msg:
                    break
                self.messages.put((socket, msg))
                reply = self.replies.get()
                socket.sendall(reply)
            except IOError as e:
                log.error("IOError on ipc socket", error=e.args)

    def receive_message(self):
        return self.messages.get()

    def send_reply(self, context, reply):
        self.replies.put(reply)


class RPCServer(BaseService):
    """Base-class for RPC-servers, can be extended for different transports.
    """

    @classmethod
    def subdispatcher_classes(cls):
        return (Web3, Personal, Net, Compilers, DB, Chain, Miner, FilterManager)

    def get_block(self, block_id=None):
        """Return the block identified by `block_id`.

        This method also sets :attr:`default_block` to the value of `block_id`
        which will be returned if, at later calls, `block_id` is not provided.

        Subdispatchers using this function have to ensure sure that a
        chainmanager is registered via :attr:`required_services`.

        :param block_id: either the block number as integer or 'pending',
                        'earliest' or 'latest', or `None` for the default
                        block
        :returns: the requested block
        :raises: :exc:`KeyError` if the block does not exist
        """
        log.debug("get_block")
        assert 'chain' in self.app.services
        chain = self.app.services.chain.chain
        if block_id is None:
            block_id = self.default_block
        else:
            self.default_block = block_id
        if block_id == 'pending':
            return self.app.services.chain.chain.head_candidate
        if block_id == 'latest':
            return chain.head
        if block_id == 'earliest':
            block_id = 0
        if is_numeric(block_id):
            # by number
            hash_ = chain.index.get_block_by_number(block_id)
        elif block_id == chain.head_candidate.hash:
            return chain.head_candidate
        else:
            # by hash
            assert is_string(block_id)
            hash_ = block_id
        return chain.get(hash_)


class IPCRPCServer(RPCServer):
    """Service providing an IPC Service over a named socket.
    Should respond to requests such as:

        >>> echo '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["latest",false]}' | socat - /tmp/geth.ipc
    """
    name = 'ipc'
    default_config = dict(ipc=dict(
        ipcpath='/tmp/pyethapp.ipc',
    ))

    def __init__(self, app):
        log.debug('initializing IPCRPCServer')
        BaseService.__init__(self, app)
        self.app = app

        self.dispatcher = LoggingDispatcher()
        # register sub dispatchers
        for subdispatcher in self.subdispatcher_classes():
            subdispatcher.register(self)

        self.ipcpath = self.config['ipc']['ipcpath']
        self.transport = IPCDomainSocketTransport(
            queue_class=gevent.queue.Queue,
            sockpath=self.ipcpath,
        )

        self.rpc_server = RPCServerGreenlets(
            self.transport,
            JSONRPCProtocol(),
            self.dispatcher
        )
        self.default_block = 'latest'

    def _run(self):
        log.info('starting IPCRPCServer', ipcpath=self.ipcpath)
        # in the main greenlet, run our rpc_server
        self.socket_server = gevent.spawn(serve, self.transport.socket, handler=self.transport.handle)
        self.rpc_server.serve_forever()

    def stop(self):
        log.info('stopping IPCRPCServer')
        if self.socket_server is not None:
            self.socket_server.kill()


class JSONRPCServer(RPCServer):
    """Service providing an HTTP server with JSON RPC interface.

    Other services can extend the JSON RPC interface by creating a
    :class:`Subdispatcher` and registering it via
    `Subdispatcher.register(self.app.services.json_rpc_server)`.

    Alternatively :attr:`dispatcher` can be extended directly (see
    https://tinyrpc.readthedocs.org/en/latest/dispatch.html).
    """

    name = 'jsonrpc'
    default_config = dict(jsonrpc=dict(
        listen_port=4000,
        listen_host='127.0.0.1',
        corsdomain='',
    ))

    def __init__(self, app):
        log.debug('initializing JSONRPCServer')
        BaseService.__init__(self, app)
        self.app = app

        self.dispatcher = LoggingDispatcher()
        # register sub dispatchers
        for subdispatcher in self.subdispatcher_classes():
            subdispatcher.register(self)

        transport = WsgiServerTransport(queue_class=gevent.queue.Queue,
                                        allow_origin=self.config['jsonrpc']['corsdomain'])
        # start wsgi server as a background-greenlet
        self.listen_port = self.config['jsonrpc']['listen_port']
        self.listen_host = self.config['jsonrpc']['listen_host']
        listener = (self.listen_host, self.listen_port)
        self.wsgi_server = gevent.wsgi.WSGIServer(listener,
                                                  transport.handle, log=WSGIServerLogger)
        self.wsgi_thread = None
        self.rpc_server = RPCServerGreenlets(
            transport,
            JSONRPCProtocol(),
            self.dispatcher
        )
        self.default_block = 'latest'

    def _run(self):
        log.info('starting JSONRPCServer', port=self.listen_port)
        # in the main greenlet, run our rpc_server
        self.wsgi_thread = gevent.spawn(self.wsgi_server.serve_forever)
        self.rpc_server.serve_forever()

    def stop(self):
        log.info('stopping JSONRPCServer')
        if self.wsgi_thread is not None:
            self.wsgi_thread.kill()


class Subdispatcher(object):

    """A JSON RPC subdispatcher which can be registered at JSONRPCService.

    :cvar prefix: common prefix shared by all rpc methods implemented by this
                  subdispatcher
    :cvar required_services: a list of names of services the subdispatcher
                             is built on and will be made available as
                             instance variables
    """

    prefix = ''
    required_services = []

    @classmethod
    def register(cls, json_rpc_service):
        """Register a new instance at ``json_rpc_service.dispatcher``.

        The subdispatcher will be able to access all required services as well
        as the app object as attributes.

        If one of the required services is not available, log this as warning
        but don't fail.
        """
        dispatcher = cls()
        for service_name in cls.required_services:
            try:
                service = json_rpc_service.app.services[service_name]
            except KeyError:
                log.warning('No {} registered. Some RPC methods will not be '
                            'available'.format(service_name))
                return
            setattr(dispatcher, service_name, service)
        dispatcher.app = json_rpc_service.app
        dispatcher.json_rpc_server = json_rpc_service
        json_rpc_service.dispatcher.register_instance(dispatcher, cls.prefix)


def quantity_decoder(data):
    """Decode `data` representing a quantity."""
    if not is_string(data):
        success = False
    elif not data.startswith('0x'):
        success = False  # must start with 0x prefix
    elif len(data) > 3 and data[2] == '0':
        success = False  # must not have leading zeros (except `0x0`)
    else:
        data = data[2:]
        # ensure even length
        if len(data) % 2 == 1:
            data = '0' + data
        try:
            return int(data, 16)
        except ValueError:
            success = False
    assert not success
    raise BadRequestError('Invalid quantity encoding')


def quantity_encoder(i):
    """Encode integer quantity `data`."""
    assert is_numeric(i)
    data = int_to_big_endian(i)
    return '0x' + (encode_hex(data).lstrip('0') or '0')


def data_decoder(data):
    """Decode `data` representing unformatted data."""
    if not data.startswith('0x'):
        data = '0x' + data

    if len(data) % 2 != 0:
        # workaround for missing leading zeros from netstats
        assert len(data) < 64 + 2
        data = '0x' + '0' * (64 - (len(data) - 2)) + data[2:]

    try:
        return decode_hex(data[2:])
    except TypeError:
        raise BadRequestError('Invalid data hex encoding', data[2:])


def data_encoder(data, length=None):
    """Encode unformatted binary `data`.

    If `length` is given, the result will be padded like this: ``data_encoder('\xff', 3) ==
    '0x0000ff'``.
    """
    s = encode_hex(data)
    if length is None:
        return '0x' + s
    else:
        return '0x' + s.rjust(length * 2, '0')


def address_decoder(data):
    """Decode an address from hex with 0x prefix to 20 bytes."""
    addr = data_decoder(data)
    if len(addr) not in (20, 0):
        raise BadRequestError('Addresses must be 20 or 0 bytes long')
    return addr


def address_encoder(address):
    assert len(address) in (20, 0)
    return '0x' + encode_hex(address)


def block_id_decoder(data):
    """Decode a block identifier as expected from :meth:`JSONRPCServer.get_block`."""
    if data in (None, 'latest', 'earliest', 'pending'):
        return data
    else:
        return quantity_decoder(data)


def block_hash_decoder(data):
    """Decode a block hash."""
    decoded = data_decoder(data)
    if len(decoded) != 32:
        raise BadRequestError('Block hashes must be 32 bytes long')
    return decoded


def tx_hash_decoder(data):
    """Decode a transaction hash."""
    decoded = data_decoder(data)
    if len(decoded) != 32:
        raise BadRequestError('Transaction hashes must be 32 bytes long')
    return decoded


def bool_decoder(data):
    if not isinstance(data, bool):
        raise BadRequestError('Parameter must be boolean')
    return data


def block_encoder(block, include_transactions=False, pending=False, is_header=False):
    """Encode a block as JSON object.

    :param block: a :class:`ethereum.blocks.Block`
    :param include_transactions: if true transactions are included, otherwise
                                 only their hashes
    :param pending: if `True` the block number of transactions, if included, is set to `None`
    :param is_header: if `True` the following attributes are ommitted: size, totalDifficulty,
                      transactions and uncles (thus, the function can be called with a block
                      header instead of a full block)
    :returns: a json encodable dictionary
    """
    assert not (include_transactions and is_header)
    d = {
        'number': quantity_encoder(block.number) if not pending else None,
        'hash': data_encoder(block.hash) if not pending else None,
        'parentHash': data_encoder(block.prevhash),
        'nonce': data_encoder(block.nonce) if not pending else None,
        'sha3Uncles': data_encoder(block.uncles_hash),
        'logsBloom': data_encoder(int_to_big_endian(block.bloom), 256) if not pending else None,
        'transactionsRoot': data_encoder(block.tx_list_root),
        'stateRoot': data_encoder(block.state_root),
        'miner': data_encoder(block.coinbase) if not pending else None,
        'difficulty': quantity_encoder(block.difficulty),
        'extraData': data_encoder(block.extra_data),
        'gasLimit': quantity_encoder(block.gas_limit),
        'gasUsed': quantity_encoder(block.gas_used),
        'timestamp': quantity_encoder(block.timestamp),
    }
    if not is_header:
        d['totalDifficulty'] = quantity_encoder(block.chain_difficulty())
        d['size'] = quantity_encoder(len(rlp.encode(block)))
        d['uncles'] = [data_encoder(u.hash) for u in block.uncles]
        if include_transactions:
            d['transactions'] = []
            for i, tx in enumerate(block.get_transactions()):
                d['transactions'].append(tx_encoder(tx, block, i, pending))
        else:
            d['transactions'] = [data_encoder(tx.hash) for tx in block.get_transactions()]
    return d


def tx_encoder(transaction, block, i, pending):
    """Encode a transaction as JSON object.

    `transaction` is the `i`th transaction in `block`. `pending` specifies if
    the block is pending or already mined.
    """
    return {
        'hash': data_encoder(transaction.hash),
        'nonce': quantity_encoder(transaction.nonce),
        'blockHash': data_encoder(block.hash),
        'blockNumber': quantity_encoder(block.number) if not pending else None,
        'transactionIndex': quantity_encoder(i),
        'from': data_encoder(transaction.sender),
        'to': data_encoder(transaction.to),
        'value': quantity_encoder(transaction.value),
        'gasPrice': quantity_encoder(transaction.gasprice),
        'gas': quantity_encoder(transaction.startgas),
        'input': data_encoder(transaction.data),
    }


def loglist_encoder(loglist):
    """Encode a list of log"""
    # l = []
    # if len(loglist) > 0 and loglist[0] is None:
    #     assert all(element is None for element in l)
    #     return l
    result = []
    for l in loglist:
        result.append({
            'logIndex': quantity_encoder(l['log_idx']) if not l['pending'] else None,
            'transactionIndex': quantity_encoder(l['tx_idx']) if not l['pending'] else None,
            'transactionHash': data_encoder(l['txhash']) if not l['pending'] else None,
            'blockHash': data_encoder(l['block'].hash) if not l['pending'] else None,
            'blockNumber': quantity_encoder(l['block'].number) if not l['pending'] else None,
            'address': address_encoder(l['log'].address),
            'data': data_encoder(l['log'].data),
            'topics': [data_encoder(int_to_big_endian(topic), 32) for topic in l['log'].topics],
            'type': 'pending' if l['pending'] else 'mined'
        })
    return result


def filter_decoder(filter_dict, chain):
    """Decodes a filter as expected by eth_newFilter or eth_getLogs to a :class:`Filter`."""
    if not isinstance(filter_dict, dict):
        raise BadRequestError('Filter must be an object')
    address = filter_dict.get('address', None)
    if is_string(address):
        addresses = [address_decoder(address)]
    elif isinstance(address, Iterable):
        addresses = [address_decoder(addr) for addr in address]
    elif address is None:
        addresses = None
    else:
        raise JSONRPCInvalidParamsError('Parameter must be address or list of addresses')
    if 'topics' in filter_dict:
        topics = []
        for topic in filter_dict['topics']:
            if type(topic) == list:
                or_topics = []
                for or_topic in topic:
                    or_topics.append(big_endian_to_int(data_decoder(or_topic)))
                topics.append(or_topics)
            elif topic is not None:
                log.debug('with topic', topic=topic)
                log.debug('decoded', topic=data_decoder(topic))
                log.debug('int', topic=big_endian_to_int(data_decoder(topic)))
                topics.append(big_endian_to_int(data_decoder(topic)))
            else:
                topics.append(None)
    else:
        topics = None

    from_block = filter_dict.get('fromBlock') or 'latest'
    to_block = filter_dict.get('toBlock') or 'latest'

    try:
        from_block = quantity_decoder(from_block)
    except BadRequestError:
        if from_block not in ('earliest', 'latest', 'pending'):
            raise JSONRPCInvalidParamsError('fromBlock must be block number, "earliest", "latest" '
                                            'or pending')
    try:
        to_block = quantity_decoder(to_block)
    except BadRequestError:
        if to_block not in ('earliest', 'latest', 'pending'):
            raise JSONRPCInvalidParamsError('toBlock must be block number, "earliest", "latest" '
                                            'or pending')

    # check order
    block_id_dict = {
        'earliest': 0,
        'latest': chain.head.number,
        'pending': chain.head_candidate.number
    }
    range_ = [b if is_numeric(b) else block_id_dict[b] for b in (from_block, to_block)]
    if range_[0] > range_[1]:
        raise JSONRPCInvalidParamsError('fromBlock must not be newer than toBlock')

    return LogFilter(chain, from_block, to_block, addresses, topics)


def decode_arg(name, decoder):
    """Create a decorator that applies `decoder` to argument `name`."""
    @decorator
    def new_f(f, *args, **kwargs):
        call_args = inspect.getcallargs(f, *args, **kwargs)
        call_args[name] = decoder(call_args[name])
        return f(**call_args)
    return new_f


def encode_res(encoder):
    """Create a decorator that applies `encoder` to the return value of the
    decorated function.
    """
    @decorator
    def new_f(f, *args, **kwargs):
        res = f(*args, **kwargs)
        return encoder(res)
    return new_f


class Personal(Subdispatcher):

    """Subdispatcher for account-related RPC methods.

    NOTE: this does not seem to be part of the official JSON-RPC specs but instead part of
    go-ethereum's JavaScript-Console: https://github.com/ethereum/go-ethereum/wiki/JavaScript-Console#personal

    It is needed for MIST-IPC.
    """

    prefix = 'personal_'

    @public
    @decode_arg('account_address', address_decoder)
    def unlockAccount(self, account_address, passwd, duration):
        if account_address in self.app.services.accounts:
            account = self.app.services.accounts.get_by_address(account_address)
            account.unlock(passwd)
            gevent.spawn_later(duration, lambda: account.lock())
            return not account.locked
        else:
            return False

    @public
    @encode_res(address_encoder)
    def newAccount(self, passwd):
        account = Account.new(passwd)
        account.path = os.path.join(self.app.services.accounts.keystore_dir, account.address.encode('hex'))
        self.app.services.accounts.add_account(account)
        account.lock()
        assert account.locked
        assert self.app.services.accounts.find(account.address.encode('hex'))
        return account.address


class Web3(Subdispatcher):

    """Subdispatcher for some generic RPC methods."""

    prefix = 'web3_'

    @public
    @decode_arg('data', data_decoder)
    @encode_res(data_encoder)
    def sha3(self, data):
        return sha3(data)

    @public
    def clientVersion(self):
        return "{s.app.client_name}/{s.app.client_version}".format(s=self)


class Net(Subdispatcher):

    """Subdispatcher for network related RPC methods."""

    prefix = 'net_'
    required_services = ['discovery', 'peermanager']

    @public
    def version(self):
        return str(self.discovery.protocol.version)

    @public
    def listening(self):
        return self.peermanager.num_peers() < self.peermanager.config['p2p']['min_peers']

    @public
    @encode_res(quantity_encoder)
    def peerCount(self):
        return self.peermanager.num_peers()


class Compilers(Subdispatcher):

    """Subdispatcher for compiler related RPC methods."""

    prefix = 'eth_'
    required_services = []

    def __init__(self):
        super(Compilers, self).__init__()
        self.compilers_ = None

    @property
    def compilers(self):
        if self.compilers_ is None:
            self.compilers_ = {}
            try:
                import serpent
                self.compilers_['serpent'] = serpent.compile
                self.compilers_['lll'] = serpent.compile_lll
            except ImportError:
                pass
            try:
                import ethereum._solidity
                s = ethereum._solidity.get_solidity()
                if s:
                    self.compilers_['solidity'] = s.compile_rich
                else:
                    log.warn('could not import solidity')
            except ImportError:
                pass
        return self.compilers_

    @public
    def getCompilers(self):
        return self.compilers.keys()

    @public
    def compileSolidity(self, code):
        try:
            return self.compilers['solidity'](code)
        except KeyError:
            raise MethodNotFoundError()

    @public
    @encode_res(data_encoder)
    def compileSerpent(self, code):
        try:
            return self.compilers['serpent'](code)
        except KeyError:
            raise MethodNotFoundError()

    @public
    @encode_res(data_encoder)
    def compileLLL(self, code):
        try:
            return self.compilers['lll'](code)
        except KeyError:
            raise MethodNotFoundError()


class Miner(Subdispatcher):

    prefix = 'eth_'

    @public
    def mining(self):
        if 'pow' in self.app.services:
            return self.app.services.pow.active
        return False

    @public
    @encode_res(quantity_encoder)
    def hashrate(self):
        if self.mining():
            return self.app.services.pow.hashrate
        return 0

    @public
    @encode_res(address_encoder)
    def coinbase(self):
        cb = self.app.services.accounts.coinbase
        assert len(cb) == 20
        return cb

    @public
    @encode_res(quantity_encoder)
    def gasPrice(self):
        return 1  # FIXME (check latest txs)

    @public
    def accounts(self):
        return [address_encoder(account.address) for account in self.app.services.accounts]


class DB(Subdispatcher):

    """Subdispatcher providing database related RPC methods."""

    prefix = 'db_'
    required_services = ['db']

    @public
    def putString(self, db_name, key, value):
        self.db.put(db_name + key, value)
        return True

    @public
    def getString(self, db_name, key):
        try:
            return self.db.get(db_name + key)
        except KeyError:
            return ''

    @public
    @decode_arg('value', data_decoder)
    def putHex(self, db_name, key, value):
        self.db.put(db_name + key, value)
        return True

    @public
    @encode_res(data_encoder)
    def getHex(self, db_name, key):
        try:
            return self.db.get(db_name + key)
        except KeyError:
            return ''


class Chain(Subdispatcher):

    """Subdispatcher for methods to query the block chain."""

    prefix = 'eth_'
    required_services = ['chain']

    @public
    def protocolVersion(self):
        return str(ETHProtocol.version)

    @public
    def syncing(self):
        if not self.chain.is_syncing:
            return False
        else:
            synctask = self.chain.synchronizer.synctask
            result = dict(
                startingBlock=synctask.start_block_number,
                currentBlock=self.chain.chain.head.number,
                highestBlock=synctask.end_block_number,
            )
            return {k: quantity_encoder(v) for k, v in result.items()}

    @public
    @encode_res(quantity_encoder)
    def blockNumber(self):
        return self.chain.chain.head.number

    @public
    @decode_arg('address', address_decoder)
    @decode_arg('block_id', block_id_decoder)
    @encode_res(quantity_encoder)
    def getBalance(self, address, block_id=None):
        block = self.json_rpc_server.get_block(block_id)
        return block.get_balance(address)

    @public
    @decode_arg('address', address_decoder)
    @decode_arg('index', quantity_decoder)
    @decode_arg('block_id', block_id_decoder)
    def getStorageAt(self, address, index, block_id=None):
        block = self.json_rpc_server.get_block(block_id)
        i = block.get_storage_data(address, index)
        assert is_numeric(i)
        return data_encoder(int_to_big_endian(i), length=32)

    @public
    @decode_arg('address', address_decoder)
    @decode_arg('block_id', block_id_decoder)
    @encode_res(quantity_encoder)
    def getTransactionCount(self, address, block_id='pending'):
        block = self.json_rpc_server.get_block(block_id)
        return block.get_nonce(address) - \
            self.json_rpc_server.config['eth']['block']['ACCOUNT_INITIAL_NONCE']

    @public
    @decode_arg('block_hash', block_hash_decoder)
    def getBlockTransactionCountByHash(self, block_hash):
        try:
            block = self.json_rpc_server.get_block(block_hash)
        except KeyError:
            return None
        else:
            return quantity_encoder(block.transaction_count)

    @public
    @decode_arg('block_id', block_id_decoder)
    def getBlockTransactionCountByNumber(self, block_id):
        try:
            block = self.json_rpc_server.get_block(block_id)
        except KeyError:
            return None
        else:
            return quantity_encoder(block.transaction_count)

    @public
    @decode_arg('block_hash', block_hash_decoder)
    def getUncleCountByBlockHash(self, block_hash):
        try:
            block = self.json_rpc_server.get_block(block_hash)
        except KeyError:
            return None
        else:
            return quantity_encoder(len(block.uncles))

    @public
    @decode_arg('block_id', block_id_decoder)
    def getUncleCountByBlockNumber(self, block_id):
        try:
            if block_id == u'pending':
                return None
            block = self.json_rpc_server.get_block(block_id)
        except KeyError:
            return None
        else:
            return quantity_encoder(len(block.uncles))

    @public
    @decode_arg('address', address_decoder)
    @decode_arg('block_id', block_id_decoder)
    @encode_res(data_encoder)
    def getCode(self, address, block_id=None):
        block = self.json_rpc_server.get_block(block_id)
        return block.get_code(address)

    @public
    @decode_arg('block_hash', block_hash_decoder)
    @decode_arg('include_transactions', bool_decoder)
    def getBlockByHash(self, block_hash, include_transactions):
        try:
            block = self.json_rpc_server.get_block(block_hash)
        except KeyError:
            return None
        return block_encoder(block, include_transactions)

    @public
    @decode_arg('block_id', block_id_decoder)
    @decode_arg('include_transactions', bool_decoder)
    def getBlockByNumber(self, block_id, include_transactions):
        try:
            block = self.json_rpc_server.get_block(block_id)
        except KeyError:
            return None
        return block_encoder(block, include_transactions, pending=block_id == 'pending')

    @public
    @decode_arg('tx_hash', tx_hash_decoder)
    def getTransactionByHash(self, tx_hash):
        try:
            tx, block, index = self.chain.chain.index.get_transaction(tx_hash)
            if self.chain.chain.in_main_branch(block):
                return tx_encoder(tx, block, index, False)
        except KeyError:
            return None
        return None

    @public
    @decode_arg('block_hash', block_hash_decoder)
    @decode_arg('index', quantity_decoder)
    def getTransactionByBlockHashAndIndex(self, block_hash, index):
        block = self.json_rpc_server.get_block(block_hash)
        try:
            tx = block.get_transaction(index)
        except IndexError:
            return None
        return tx_encoder(tx, block, index, False)

    @public
    @decode_arg('block_id', block_id_decoder)
    @decode_arg('index', quantity_decoder)
    def getTransactionByBlockNumberAndIndex(self, block_id, index):
        block = self.json_rpc_server.get_block(block_id)
        try:
            tx = block.get_transaction(index)
        except IndexError:
            return None
        return tx_encoder(tx, block, index, block_id == 'pending')

    @public
    @decode_arg('block_hash', block_hash_decoder)
    @decode_arg('index', quantity_decoder)
    def getUncleByBlockHashAndIndex(self, block_hash, index):
        try:
            block = self.json_rpc_server.get_block(block_hash)
            uncle = block.uncles[index]
        except (IndexError, KeyError):
            return None
        return block_encoder(uncle, is_header=True)

    @public
    @decode_arg('block_id', block_id_decoder)
    @decode_arg('index', quantity_decoder)
    def getUncleByBlockNumberAndIndex(self, block_id, index):
        try:
            # TODO: think about moving this check into the Block.uncles property
            if block_id == u'pending':
                return None
            block = self.json_rpc_server.get_block(block_id)
            uncle = block.uncles[index]
        except (IndexError, KeyError):
            return None
        return block_encoder(uncle, is_header=True)

    @public
    def getWork(self):
        print 'Sending work...'
        h = self.chain.chain.head_candidate
        return [
            encode_hex(h.header.mining_hash),
            encode_hex(h.header.seed),
            encode_hex(zpad(int_to_big_endian(2 ** 256 // h.header.difficulty), 32))
        ]

    @public
    def test(self, nonce):
        print 80808080808
        return nonce

    @public
    @encode_res(quantity_encoder)
    def gasLimit(self):
        return self.json_rpc_server.get_block('latest').gas_limit

    @public
    @encode_res(quantity_encoder)
    def lastGasPrice(self):
        txs = self.json_rpc_server.get_block('latest').get_transactions()
        if txs:
            return min(tx.gasprice for tx in txs)
        return 0

    @public
    @decode_arg('nonce', data_decoder)
    @decode_arg('mining_hash', data_decoder)
    @decode_arg('mix_digest', data_decoder)
    def submitWork(self, nonce, mining_hash, mix_digest):
        print 'submitting work'
        h = self.chain.chain.head_candidate
        print 'header: %s' % encode_hex(rlp.encode(h))
        if h.header.mining_hash != mining_hash:
            return False
        print 'mining hash: %s' % encode_hex(mining_hash)
        print 'nonce: %s' % encode_hex(nonce)
        print 'mixhash: %s' % encode_hex(mix_digest)
        print 'seed: %s' % encode_hex(h.header.seed)
        h.header.nonce = nonce
        h.header.mixhash = mix_digest
        if not h.header.check_pow():
            print 'PoW check false'
            return False
        print 'PoW check true'
        self.chain.chain.add_block(h)
        self.chain.broadcast_newblock(h)
        print 'Added: %d' % h.header.number
        return True

    @public
    @encode_res(data_encoder)
    def coinbase(self):
        return self.app.services.accounts.coinbase

    @public
    @decode_arg('address', address_decoder)
    @decode_arg('block_id', block_id_decoder)
    @encode_res(quantity_encoder)
    def nonce(self, address, block_id='pending'):
        """
        Return the `nonce` for `address` at the current `block_id
        :param address:
        :param block_id:
        :return: the next nonce for the address/account
        """
        assert address is not None
        block = self.json_rpc_server.get_block(block_id)
        assert block is not None
        nonce = block.get_nonce(address)
        assert nonce is not None and isinstance(nonce, int)
        return nonce

    @public
    def sendTransaction(self, data):
        """
        extend spec to support v,r,s signed transactions
        """
        if not isinstance(data, dict):
            raise BadRequestError('Transaction must be an object')

        def get_data_default(key, decoder, default=None):
            if key in data:
                return decoder(data[key])
            return default

        to = get_data_default('to', address_decoder, b'')
        gas_key = 'gas' if 'gas' in data else 'startgas'
        startgas = get_data_default(gas_key, quantity_decoder, default_startgas)
        gasprice_key = 'gasPrice' if 'gasPrice' in data else 'gasprice'
        gasprice = get_data_default(gasprice_key, quantity_decoder, default_gasprice)
        value = get_data_default('value', quantity_decoder, 0)
        data_ = get_data_default('data', data_decoder, b'')
        v = signed = get_data_default('v', quantity_decoder, 0)
        r = get_data_default('r', quantity_decoder, 0)
        s = get_data_default('s', quantity_decoder, 0)
        nonce = get_data_default('nonce', quantity_decoder, None)
        sender = get_data_default('from', address_decoder, self.app.services.accounts.coinbase)
        assert len(sender) == 20

        # create transaction
        if signed:
            assert nonce is not None, 'signed but no nonce provided'
            assert v and r and s
        else:
            if nonce is None or nonce == 0:
                nonce = self.app.services.chain.chain.head_candidate.get_nonce(sender)

        tx = Transaction(nonce, gasprice, startgas, to, value, data_, v, r, s)
        tx._sender = None
        if not signed:
            assert sender in self.app.services.accounts, 'can not sign: no account for sender'
            self.app.services.accounts.sign_tx(sender, tx)
        self.app.services.chain.add_transaction(tx, origin=None, force_broadcast=True)
        log.debug('decoded tx', tx=tx.log_dict())
        return data_encoder(tx.hash)

    @public
    @decode_arg('data', data_decoder)
    def sendRawTransaction(self, data):
        """
        decode sendRawTransaction request data, format it and relay along to the sendTransaction method
        to ensure the same validations and processing rules are applied
        """
        tx_data = rlp.codec.decode(data, ethereum.transactions.Transaction)

        tx_dict = tx_data.to_dict()
        # encode addresses
        tx_dict['from'] = address_encoder(tx_dict.get('sender', ''))
        to_value = tx_dict.get('to', '')
        if to_value:
            tx_dict['to'] = address_encoder(to_value)

        # encode data
        tx_dict['data'] = data_encoder(tx_dict.get('data', b''))

        # encode quantities included in the raw transaction data
        gasprice_key = 'gasPrice' if 'gasPrice' in tx_dict else 'gasprice'
        gas_key = 'gas' if 'gas' in tx_dict else 'startgas'
        for key in ('value', 'nonce', gas_key, gasprice_key, 'v', 'r', 's'):
            if key in tx_dict:
                tx_dict[key] = quantity_encoder(tx_dict[key])

        # relay the information along to the sendTransaction method for processing
        return self.sendTransaction(tx_dict)

    @public
    @decode_arg('block_id', block_id_decoder)
    @encode_res(data_encoder)
    def call(self, data, block_id='pending'):
        block = self.json_rpc_server.get_block(block_id)
        snapshot_before = block.snapshot()
        tx_root_before = snapshot_before['txs'].root_hash  # trie object in snapshot is mutable

        # rebuild block state before finalization
        if block.has_parent():
            parent = block.get_parent()
            test_block = block.init_from_parent(parent, block.coinbase,
                                                timestamp=block.timestamp)
            for tx in block.get_transactions():
                success, output = processblock.apply_transaction(test_block, tx)
                assert success
        else:
            env = ethereum.config.Env(db=block.db)
            test_block = ethereum.blocks.genesis(env)
            original = {key: value for key, value in snapshot_before.items() if key != 'txs'}
            original = deepcopy(original)
            original['txs'] = Trie(snapshot_before['txs'].db, snapshot_before['txs'].root_hash)
            test_block = ethereum.blocks.genesis(env)
            test_block.revert(original)

        # validate transaction
        if not isinstance(data, dict):
            raise BadRequestError('Transaction must be an object')
        to = address_decoder(data['to'])
        try:
            startgas = quantity_decoder(data['gas'])
        except KeyError:
            startgas = test_block.gas_limit - test_block.gas_used
        try:
            gasprice = quantity_decoder(data['gasPrice'])
        except KeyError:
            gasprice = 0
        try:
            value = quantity_decoder(data['value'])
        except KeyError:
            value = 0
        try:
            data_ = data_decoder(data['data'])
        except KeyError:
            data_ = b''
        try:
            sender = address_decoder(data['from'])
        except KeyError:
            sender = '\x00' * 20

        # apply transaction
        nonce = test_block.get_nonce(sender)
        tx = Transaction(nonce, gasprice, startgas, to, value, data_)
        tx.sender = sender

        try:
            success, output = processblock.apply_transaction(test_block, tx)
        except InvalidTransaction:
            success = False
        # make sure we didn't change the real state
        snapshot_after = block.snapshot()
        assert snapshot_after == snapshot_before
        assert snapshot_after['txs'].root_hash == tx_root_before

        if success:
            return output
        else:
            return False

    @public
    @decode_arg('block_id', block_id_decoder)
    @encode_res(quantity_encoder)
    def estimateGas(self, data, block_id='pending'):
        block = self.json_rpc_server.get_block(block_id)
        snapshot_before = block.snapshot()
        tx_root_before = snapshot_before['txs'].root_hash  # trie object in snapshot is mutable

        # rebuild block state before finalization
        if block.has_parent():
            parent = block.get_parent()
            test_block = block.init_from_parent(parent, block.coinbase,
                                                timestamp=block.timestamp)
            for tx in block.get_transactions():
                success, output = processblock.apply_transaction(test_block, tx)
                assert success
        else:
            test_block = ethereum.blocks.genesis(block.db)
            original = {key: value for key, value in snapshot_before.items() if key != 'txs'}
            original = deepcopy(original)
            original['txs'] = Trie(snapshot_before['txs'].db, snapshot_before['txs'].root_hash)
            test_block = ethereum.blocks.genesis(block.db)
            test_block.revert(original)

        # validate transaction
        if not isinstance(data, dict):
            raise BadRequestError('Transaction must be an object')
        to = address_decoder(data['to'])
        try:
            startgas = quantity_decoder(data['gas'])
        except KeyError:
            startgas = block.gas_limit - block.gas_used
        try:
            gasprice = quantity_decoder(data['gasPrice'])
        except KeyError:
            gasprice = 0
        try:
            value = quantity_decoder(data['value'])
        except KeyError:
            value = 0
        try:
            data_ = data_decoder(data['data'])
        except KeyError:
            data_ = b''
        try:
            sender = address_decoder(data['from'])
        except KeyError:
            sender = '\x00' * 20

        # apply transaction
        nonce = test_block.get_nonce(sender)
        tx = Transaction(nonce, gasprice, startgas, to, value, data_)
        tx.sender = sender

        try:
            success, output = processblock.apply_transaction(test_block, tx)
        except InvalidTransaction:
            success = False
        # make sure we didn't change the real state
        snapshot_after = block.snapshot()
        assert snapshot_after == snapshot_before
        assert snapshot_after['txs'].root_hash == tx_root_before

        return test_block.gas_used - block.gas_used


class LogFilter(object):

    """A filter for logs.

    :ivar chain: the blockchain object
    :ivar first_block: number of the first block to check or 'latest', 'pending', 'earliest'
    :ivar last_block: number of the last block to check or 'latest', 'pending', 'earliest'
    :ivar addresses: a list of contract addresses or None to not consider addresses
    :ivar topics: a list of topics or `None` to not consider topics
    :ivar log_dict: a list of dicts for each found log (with keys `'log'`, `'log_idx'`, `'block'`,
                    `'tx_hash'` and `'tx_idx'`)
    :ivar last_head: head at the time of last check or initialization
    :ivar last_block_checked: the highest block in the chain that does not have to be checked for
                              logs again or `None` if no block has been checked yet
    """

    def __init__(self, chain, first_block, last_block, addresses=None, topics=None):
        self.chain = chain
        assert is_numeric(first_block) or first_block in ('latest', 'pending', 'earliest')
        assert is_numeric(last_block) or last_block in ('latest', 'pending', 'earliest')
        self.first_block = first_block
        self.last_block = last_block
        self.addresses = addresses
        self.topics = topics
        if self.topics:
            for topic in self.topics:
                assert topic is None or is_numeric(topic) \
                    or type(topic) == list
                if type(topic) == list:
                    for or_topic in topic:
                        assert or_topic is None or is_numeric(or_topic)

        self.last_head = self.chain.head
        self.last_block_checked = None
        self.log_dict = {}
        log.debug('new filter', filter=self, topics=self.topics)

    def __repr__(self):
        return '<LogFilter(addresses=%r, topics=%r, first=%r, last=%r)>' \
            % (self.addresses, self.topics, self.first_block, self.last_block)

    def check(self):
        """Check for logs, return new ones.

        This method walks through the blocks given by :attr:`first_block` and :attr:`last_block`,
        looks at the contained logs, and collects the ones that match the filter. On subsequent
        runs blocks that have already been checked are skipped (except for the pending block, which
        may have changed since).

        :returns: dictionary of new the logs that have been added to :attr:`logs`.
        """
        block_id_dict = {
            'earliest': 0,
            'latest': self.chain.head.number,
            'pending': self.chain.head_candidate.number
        }
        if is_numeric(self.first_block):
            first = self.first_block
        else:
            # for latest and pending we check every new block that once has been latest or pending
            first = min(self.last_head.number + 1, block_id_dict[self.first_block])
        if is_numeric(self.last_block):
            last = self.last_block
        else:
            last = block_id_dict[self.last_block]
        assert first <= last

        # skip blocks that have already been checked
        if self.last_block_checked is not None:
            print self.last_block_checked
            first = max(self.last_block_checked.number + 1, first)
            if first > last:
                return {}

        blocks_to_check = []
        for n in range(first, last):
            blocks_to_check.append(self.chain.index.get_block_by_number(n))
        # last block may be head candidate, which cannot be retrieved via get_block_by_number
        if last == self.chain.head_candidate.number:
            blocks_to_check.append(self.chain.head_candidate)
        else:
            blocks_to_check.append(self.chain.get(self.chain.index.get_block_by_number(last)))
        logger.debug('obtained block hashes to check with filter', numhashes=len(blocks_to_check))

        # go through all receipts of all blocks
        # logger.debug('blocks to check', blocks=blocks_to_check)
        new_logs = {}

        for i, block in enumerate(blocks_to_check):
            if not isinstance(block, (ethereum.blocks.Block, ethereum.blocks.CachedBlock)):
                _bloom = self.chain.get_bloom(block)
                # Check that the bloom for this block contains at least one of the desired
                # addresses
                if self.addresses:
                    pass_address_check = False
                    for address in self.addresses:
                        if bloom.bloom_query(_bloom, address):
                            pass_address_check = True
                    if not pass_address_check:
                        continue
                # Check that the bloom for this block contains all of the desired topics
                or_topics = list()
                and_topics = list()
                for topic in self.topics or []:
                    if type(topic) == list:
                        or_topics += topic
                    else:
                        and_topics.append(topic)
                if or_topics:
                    # In case of the frequent usage of multiple 'or' statements in the filter
                    # the following logic should be optimized so that the fewer amount of blocks gets checked.
                    # It is currently optimal for filters with a single 'or' statement.
                    _topic_and_bloom = bloom.bloom_from_list(map(int32.serialize, and_topics or []))
                    bloom_passed = False
                    for or_t in or_topics:
                        or_bl = bloom.bloom_from_list(map(int32.serialize, [or_t]))
                        if bloom.bloom_combine(_bloom, _topic_and_bloom, or_bl) == _bloom:
                            bloom_passed = True
                            break
                    if not bloom_passed:
                        continue
                else:
                    _topic_bloom = bloom.bloom_from_list(map(int32.serialize, self.topics or []))
                    if bloom.bloom_combine(_bloom, _topic_bloom) != _bloom:
                        continue
                block = self.chain.get(block)
                print 'bloom filter passed'
            logger.debug('-')
            logger.debug('with block', block=block)
            receipts = block.get_receipts()
            logger.debug('receipts', block=block, receipts=receipts)
            for r_idx, receipt in enumerate(receipts):  # one receipt per tx
                for l_idx, log in enumerate(receipt.logs):
                    logger.debug('log', log=log)
                    if self.topics is not None:
                        # compare topics one by one
                        topic_match = True
                        if len(log.topics) < len(self.topics):
                            topic_match = False
                        for filter_topic, log_topic in zip(self.topics, log.topics):
                            if filter_topic is not None and filter_topic != log_topic:
                                if type(filter_topic) == list:
                                    if log_topic not in filter_topic:
                                        logger.debug('topic mismatch', want=filter_topic, have=log_topic)
                                        topic_match = False
                                else:
                                    logger.debug('topic mismatch', want=filter_topic, have=log_topic)
                                    topic_match = False
                        if not topic_match:
                            continue
                    # check for address
                    if self.addresses is not None and log.address not in self.addresses:
                        continue
                    # still here, so match was successful => add to log list
                    tx = block.get_transaction(r_idx)
                    id_ = ethereum.utils.sha3(''.join((tx.hash, str(l_idx))))
                    pending = block == self.chain.head_candidate
                    r = dict(log=log, log_idx=l_idx, block=block, txhash=tx.hash, tx_idx=r_idx,
                             pending=pending)
                    logger.debug('FOUND LOG', id=id_.encode('hex'))
                    new_logs[id_] = r  # (log, i, block)
        # don't check blocks again, that have been checked already and won't change anymore
        self.last_block_checked = blocks_to_check[-1]
        if blocks_to_check[-1] != self.chain.head_candidate:
            self.last_block_checked = blocks_to_check[-1]
        else:
            self.last_block_checked = blocks_to_check[-2] if len(blocks_to_check) >= 2 else None
        if self.last_block_checked and not isinstance(self.last_block_checked, (ethereum.blocks.Block, ethereum.blocks.CachedBlock)):
            self.last_block_checked = self.chain.get(self.last_block_checked)
        actually_new_ids = new_logs.viewkeys() - self.log_dict.viewkeys()
        self.log_dict.update(new_logs)
        return {id_: new_logs[id_] for id_ in actually_new_ids}

    @property
    def logs(self):
        self.check()
        return self.log_dict.values()

    @property
    def new_logs(self):
        d = self.check()
        return d.values()


class BlockFilter(object):

    """A filter for new blocks.

    Note that "new" refers to block numbers. In case of chain reorganizations this may mean that
    some blocks are missed.

    :ivar chain: the block chain
    :ivar latest_block: the newest block that will not be returned when :meth:`check` is called
    """

    def __init__(self, chain):
        self.chain = chain
        self.latest_block = self.chain.head

    def check(self):
        """Check for new blocks.

        :returns: a list of all blocks in the chain that are newer than :attr:`latest_block`.
        """
        log.debug('checking BlockFilter')
        new_blocks = []
        block = self.chain.head
        while block.number > self.latest_block.number:
            new_blocks.append(block)
            block = block.get_parent()
        assert block.number == self.latest_block.number
        if block != self.latest_block:
            log.warning('previous latest block not in current chain',
                        prev_latest=self.latest_block.hash, replaced_by=new_blocks[-1].hash)
        if len(new_blocks) > 0:
            self.latest_block = new_blocks[0]
            log.debug('new blocks found', n=len(new_blocks))
        else:
            log.debug('no new blocks found')
        return reversed(new_blocks)


class PendingTransactionFilter(object):

    """A filter for new transactions. This includes transactions in the pending block.

    :ivar chain: the block chain
    :ivar latest_block: the latest block that has been checked for transactions at least once
    :ivar reported_txs: txs from the (formerly) pending block which don't have to be reported again
    """

    def __init__(self, chain):
        self.chain = chain
        self.latest_block = self.chain.head_candidate
        self.reported_txs = []  # needs only to contain txs from latest block

    def check(self):
        """Check for new transactions and return them."""
        # check current pending block first
        pending_txs = self.chain.head_candidate.get_transactions()
        new_txs = list(reversed([tx for tx in pending_txs if tx not in self.reported_txs]))
        # now check all blocks which have already been finalized
        block = self.chain.head_candidate.get_parent()
        while block.number >= self.latest_block.number:
            for tx in reversed(block.get_transactions()):
                if tx not in self.reported_txs:
                    new_txs.append(tx)
            block = block.get_parent()
        self.latest_block = self.chain.head_candidate
        self.reported_txs = pending_txs
        return reversed(new_txs)


class FilterManager(Subdispatcher):

    prefix = 'eth_'
    required_services = ['chain']

    def __init__(self):
        self.filters = {}
        self.next_id = 0

    @public
    @encode_res(quantity_encoder)
    def newFilter(self, filter_dict):
        filter_ = filter_decoder(filter_dict, self.chain.chain)
        self.filters[self.next_id] = filter_
        self.next_id += 1
        return self.next_id - 1

    @public
    @encode_res(quantity_encoder)
    def newBlockFilter(self):
        filter_ = BlockFilter(self.chain.chain)
        self.filters[self.next_id] = filter_
        self.next_id += 1
        return self.next_id - 1

    @public
    @encode_res(quantity_encoder)
    def newPendingTransactionFilter(self):
        filter_ = PendingTransactionFilter(self.chain.chain)
        self.filters[self.next_id] = filter_
        self.next_id += 1
        return self.next_id - 1

    @public
    @decode_arg('id_', quantity_decoder)
    def uninstallFilter(self, id_):
        try:
            self.filters.pop(id_)
            return True
        except KeyError:
            return False

    @public
    @decode_arg('id_', quantity_decoder)
    def getFilterChanges(self, id_):
        if id_ not in self.filters:
            raise BadRequestError('Unknown filter')
        filter_ = self.filters[id_]
        logger.debug('filter found', filter=filter_)
        if isinstance(filter_, (BlockFilter, PendingTransactionFilter)):
            # For filters created with eth_newBlockFilter or eth_newPendingTransactionFilter the
            # return are hashes (DATA, 32 Bytes), e.g. ["0x3454645634534..."].
            r = filter_.check()
            return [data_encoder(block_or_tx.hash) for block_or_tx in r]
        else:
            assert isinstance(filter_, LogFilter)
            return loglist_encoder(filter_.new_logs)

    @public
    @decode_arg('id_', quantity_decoder)
    @encode_res(loglist_encoder)
    def getFilterLogs(self, id_):
        if id_ not in self.filters:
            raise BadRequestError('Unknown filter')
        filter_ = self.filters[id_]
        return filter_.logs

    @public
    @encode_res(loglist_encoder)
    def getLogs(self, filter_dict):
        filter_ = filter_decoder(filter_dict, self.chain.chain)
        return filter_.logs

    # ########### Trace ############
    def _get_block_before_tx(self, txhash):
        tx, blk, i = self.app.services.chain.chain.index.get_transaction(txhash)
        # get the state we had before this transaction
        test_blk = ethereum.blocks.Block.init_from_parent(blk.get_parent(),
                                                          blk.coinbase,
                                                          extra_data=blk.extra_data,
                                                          timestamp=blk.timestamp,
                                                          uncles=blk.uncles)
        pre_state = test_blk.state_root
        for i in range(blk.transaction_count):
            tx_lst_serialized, sr, _ = blk.get_transaction(i)
            if sha3(rlp.encode(tx_lst_serialized)) == tx.hash:
                break
            else:
                pre_state = sr
        test_blk.state.root_hash = pre_state
        return test_blk, tx, i

    def _get_trace(self, txhash):
        try:  # index
            test_blk, tx, i = self._get_block_before_tx(txhash)
        except (KeyError, TypeError):
            raise Exception('Unknown Transaction  %s' % txhash)

        # collect debug output FIXME set loglevel trace???
        recorder = LogRecorder()
        # apply tx (thread? we don't want logs from other invocations)
        self.app.services.chain.add_transaction_lock.acquire()
        processblock.apply_transaction(test_blk, tx)  # FIXME deactivate tx context switch or lock
        self.app.services.chain.add_transaction_lock.release()
        return dict(tx=txhash, trace=recorder.pop_records())

    @public
    @decode_arg('txhash', data_decoder)
    def trace_transaction(self, txhash, exclude=[]):
        assert len(txhash) == 32
        assert set(exclude) in set(('stack', 'memory', 'storage'))
        t = self._get_trace(txhash)
        for key in exclude:
            for l in t['trace']:
                if key in l:
                    del l[key]
        return t

    @public
    @decode_arg('blockhash', data_decoder)
    def trace_block(self, blockhash, exclude=[]):
        txs = []
        blk = self.app.services.chain.chain.get(blockhash)
        for i in range(blk.transaction_count):
            tx_lst_serialized, sr, _ = blk.get_transaction(i)
            txhash_hex = sha3(rlp.encode(tx_lst_serialized)).encode('hex')
            txs.append(self.trace_transaction(txhash_hex, exclude))
        return txs

    @public
    @decode_arg('tx_hash', tx_hash_decoder)
    def getTransactionReceipt(self, tx_hash):
        try:
            tx, block, index = self.chain.chain.index.get_transaction(tx_hash)
        except KeyError:
            return None
        if not self.chain.chain.in_main_branch(block):
            return None
        receipt = block.get_receipt(index)
        response = {
            'transactionHash': data_encoder(tx.hash),
            'transactionIndex': quantity_encoder(index),
            'blockHash': data_encoder(block.hash),
            'blockNumber': quantity_encoder(block.number),
            'cumulativeGasUsed': quantity_encoder(receipt.gas_used),
            'contractAddress': data_encoder(tx.creates) if tx.creates else None
        }
        if index == 0:
            response['gasUsed'] = quantity_encoder(receipt.gas_used)
        else:
            prev_receipt = block.get_receipt(index - 1)
            assert prev_receipt.gas_used < receipt.gas_used
            response['gasUsed'] = quantity_encoder(receipt.gas_used - prev_receipt.gas_used)

        logs = []
        for i, log in enumerate(receipt.logs):
            logs.append({
                'log': log,
                'log_idx': i,
                'block': block,
                'txhash': tx.hash,
                'tx_idx': index,
                'pending': False
            })
        response['logs'] = loglist_encoder(logs)
        return response


if __name__ == '__main__':
    from devp2p.app import BaseApp

    # deactivate service availability check
    for cls in JSONRPCServer.subdispatcher_classes():
        cls.required_services = []

    app = BaseApp(JSONRPCServer.default_config)
    jrpc = JSONRPCServer(app)
    dispatcher = jrpc.dispatcher

    def show_methods(dispatcher, prefix=''):
        # https://github.com/micheles/decorator/blob/3.4.1/documentation.rst
        for name, method in dispatcher.method_map.items():
            print prefix + name, inspect.formatargspec(public_methods[name])
        for sub_prefix, subdispatcher_list in dispatcher.subdispatchers.items():
            for sub in subdispatcher_list:
                show_methods(sub, prefix + sub_prefix)

    show_methods(dispatcher)
