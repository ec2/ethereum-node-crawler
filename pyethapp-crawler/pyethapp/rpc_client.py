""" A simple way of interacting to a ethereum node through JSON RPC commands. """
import logging
import time
import warnings
import json

import gevent
from ethereum.abi import ContractTranslator
from ethereum.keys import privtoaddr
from ethereum.transactions import Transaction
from ethereum.utils import denoms, int_to_big_endian, big_endian_to_int, normalize_address
from ethereum._solidity import solidity_unresolved_symbols, solidity_library_symbol, solidity_resolve_symbols
from tinyrpc.protocols.jsonrpc import JSONRPCErrorResponse, JSONRPCSuccessResponse
from tinyrpc.protocols.jsonrpc import JSONRPCProtocol
from tinyrpc.transports.http import HttpPostClientTransport

from pyethapp.jsonrpc import address_encoder as _address_encoder
from pyethapp.jsonrpc import (
    data_encoder, data_decoder, address_decoder, default_gasprice,
    default_startgas, quantity_encoder, quantity_decoder,
)

# pylint: disable=invalid-name,too-many-arguments,too-few-public-methods
# The number of arguments an it's names are determined by the JSON-RPC spec

z_address = '\x00' * 20
log = logging.getLogger(__name__)


def address_encoder(address):
    """ Normalize address and hex encode it with the additional of the '0x'
    prefix.
    """
    normalized_address = normalize_address(address, allow_blank=True)
    return _address_encoder(normalized_address)


def block_tag_encoder(val):
    if isinstance(val, int):
        return quantity_encoder(val)
    elif val and isinstance(val, bytes):
        assert val in ('latest', 'pending')
        return data_encoder(val)
    else:
        assert not val


def topic_encoder(topic):
    assert isinstance(topic, (int, long))
    return data_encoder(int_to_big_endian(topic))


def topic_decoder(topic):
    return big_endian_to_int(data_decoder(topic))


def deploy_dependencies_symbols(all_contract):
    dependencies = {}

    symbols_to_contract = dict()
    for contract_name in all_contract:
        symbol = solidity_library_symbol(contract_name)

        if symbol in symbols_to_contract:
            raise ValueError('Conflicting library names.')

        symbols_to_contract[symbol] = contract_name

    for contract_name, contract in all_contract.items():
        unresolved_symbols = solidity_unresolved_symbols(contract['bin_hex'])
        dependencies[contract_name] = [
            symbols_to_contract[unresolved]
            for unresolved in unresolved_symbols
        ]

    return dependencies


def dependencies_order_of_build(target_contract, dependencies_map):
    """ Return an ordered list of contracts that is sufficient to sucessfully
    deploys the target contract.

    Note:
        This function assumes that the `dependencies_map` is an acyclic graph.
    """
    if len(dependencies_map) == 0:
        return [target_contract]

    if target_contract not in dependencies_map:
        raise ValueError('no dependencies defined for {}'.format(target_contract))

    order = [target_contract]
    todo = list(dependencies_map[target_contract])

    while len(todo):
        target_contract = todo.pop(0)
        target_pos = len(order)

        for dependency in dependencies_map[target_contract]:
            # we need to add the current contract before all it's depedencies
            if dependency in order:
                target_pos = order.index(dependency)
            else:
                todo.append(dependency)

        order.insert(target_pos, target_contract)

    order.reverse()
    return order


class JSONRPCClientReplyError(Exception):
    pass


class JSONRPCClient(object):
    protocol = JSONRPCProtocol()

    def __init__(self, host='127.0.0.1', port=4000, print_communication=True,
                 privkey=None, sender=None, use_ssl=False, transport=None):
        "specify privkey for local signing"
        if transport is None:
            self.transport = HttpPostClientTransport('{}://{}:{}'.format(
                'https' if use_ssl else 'http', host, port), headers={'content-type': 'application/json'})
        else:
            self.transport = transport
        self.print_communication = print_communication
        self.privkey = privkey
        self._sender = sender
        self.port = port

    def __repr__(self):
        return '<JSONRPCClient @%d>' % self.port

    @property
    def sender(self):
        if self.privkey:
            return privtoaddr(self.privkey)

        if self._sender is None:
            self._sender = self.coinbase

        return self._sender

    @property
    def coinbase(self):
        """ Return the client coinbase address. """
        return address_decoder(self.call('eth_coinbase'))

    def blocknumber(self):
        """ Return the most recent block. """
        return quantity_decoder(self.call('eth_blockNumber'))

    def nonce(self, address):
        if len(address) == 40:
            address = address.decode('hex')

        try:
            res = self.call('eth_nonce', address_encoder(address), 'pending')
            return quantity_decoder(res)
        except JSONRPCClientReplyError as e:
            if e.message == 'Method not found':
                raise JSONRPCClientReplyError(
                    "'eth_nonce' is not supported by your endpoint (pyethapp only). "
                    "For transactions use server-side nonces: "
                    "('eth_sendTransaction' with 'nonce=None')")
            raise e

    def balance(self, account):
        """ Return the balance of the account of given address. """
        res = self.call('eth_getBalance', address_encoder(account), 'pending')
        return quantity_decoder(res)

    def gaslimit(self):
        return quantity_decoder(self.call('eth_gasLimit'))

    def lastgasprice(self):
        return quantity_decoder(self.call('eth_lastGasPrice'))

    def new_abi_contract(self, contract_interface, address):
        warnings.warn('deprecated, use new_contract_proxy', DeprecationWarning)
        return self.new_contract_proxy(contract_interface, address)

    def new_contract_proxy(self, contract_interface, address):
        """ Return a proxy for interacting with a smart contract.

        Args:
            contract_interface: The contract interface as defined by the json.
            address: The contract's address.
        """
        sender = self.sender or privtoaddr(self.privkey)

        return ContractProxy(
            sender,
            contract_interface,
            address,
            self.eth_call,
            self.send_transaction,
        )

    def deploy_solidity_contract(self, sender, contract_name, all_contracts,  # pylint: disable=too-many-locals
                                 libraries, constructor_parameters, timeout=None, gasprice=denoms.wei):

        if contract_name not in all_contracts:
            raise ValueError('Unkonwn contract {}'.format(contract_name))

        libraries = dict(libraries)
        contract = all_contracts[contract_name]
        contract_interface = contract['abi']
        symbols = solidity_unresolved_symbols(contract['bin_hex'])

        if symbols:
            available_symbols = map(solidity_library_symbol, all_contracts.keys())  # pylint: disable=bad-builtin

            unknown_symbols = set(symbols) - set(available_symbols)
            if unknown_symbols:
                msg = 'Cannot deploy contract, known symbols {}, unresolved symbols {}.'.format(
                    available_symbols,
                    unknown_symbols,
                )
                raise Exception(msg)

            dependencies = deploy_dependencies_symbols(all_contracts)
            deployment_order = dependencies_order_of_build(contract_name, dependencies)

            deployment_order.pop()  # remove `contract_name` from the list

            log.debug('Deploing dependencies: {}'.format(str(deployment_order)))

            for deploy_contract in deployment_order:
                dependency_contract = all_contracts[deploy_contract]

                hex_bytecode = solidity_resolve_symbols(dependency_contract['bin_hex'], libraries)
                bytecode = hex_bytecode.decode('hex')

                dependency_contract['bin_hex'] = hex_bytecode
                dependency_contract['bin'] = bytecode

                transaction_hash = self.send_transaction(
                    sender,
                    to='',
                    data=bytecode,
                    gasprice=gasprice,
                )

                self.poll(transaction_hash.decode('hex'), timeout=timeout)
                receipt = self.call('eth_getTransactionReceipt', '0x' + transaction_hash)

                contract_address = receipt['contractAddress']
                contract_address = contract_address[2:]  # remove the hexadecimal prefix 0x from the address

                libraries[deploy_contract] = contract_address

                deployed_code = self.call('eth_getCode', contract_address, 'latest')

                if deployed_code == '0x':
                    raise RuntimeError("Contract address has no code, check gas usage.")

            hex_bytecode = solidity_resolve_symbols(contract['bin_hex'], libraries)
            bytecode = hex_bytecode.decode('hex')

            contract['bin_hex'] = hex_bytecode
            contract['bin'] = bytecode

        if constructor_parameters:
            translator = ContractTranslator(contract_interface)
            parameters = translator.encode_constructor_arguments(constructor_parameters)
            bytecode = contract['bin'] + parameters
        else:
            bytecode = contract['bin']

        transaction_hash = self.send_transaction(
            sender,
            to='',
            data=bytecode,
            gasprice=gasprice,
        )

        self.poll(transaction_hash.decode('hex'), timeout=timeout)
        receipt = self.call('eth_getTransactionReceipt', '0x' + transaction_hash)
        contract_address = receipt['contractAddress']

        deployed_code = self.call('eth_getCode', contract_address, 'latest')

        if deployed_code == '0x':
            raise RuntimeError("Deployment of {} failed. Contract address has no code, check gas usage.".format(
                contract_name
            ))

        return ContractProxy(
            sender,
            contract_interface,
            contract_address,
            self.eth_call,
            self.send_transaction,
        )

    def find_block(self, condition):
        """Query all blocks one by one and return the first one for which
        `condition(block)` evaluates to `True`.
        """
        i = 0
        while True:
            block = self.call('eth_getBlockByNumber', quantity_encoder(i), True)
            if condition(block) or not block:
                return block
            i += 1

    def new_filter(self, fromBlock=None, toBlock=None, address=None, topics=None):
        """ Creates a filter object, based on filter options, to notify when
        the state changes (logs). To check if the state has changed, call
        eth_getFilterChanges.
        """

        json_data = {
            'fromBlock': block_tag_encoder(fromBlock or ''),
            'toBlock': block_tag_encoder(toBlock or ''),
        }

        if address is not None:
            json_data['address'] = address_encoder(address)

        if topics is not None:
            if not isinstance(topics, list):
                raise ValueError('topics must be a list')

            json_data['topics'] = [topic_encoder(topic) for topic in topics]

        filter_id = self.call('eth_newFilter', json_data)
        return quantity_decoder(filter_id)

    def filter_changes(self, fid):
        changes = self.call('eth_getFilterChanges', quantity_encoder(fid))
        if not changes:
            return None
        elif isinstance(changes, bytes):
            return data_decoder(changes)
        else:
            decoders = dict(blockHash=data_decoder,
                            transactionHash=data_decoder,
                            data=data_decoder,
                            address=address_decoder,
                            topics=lambda x: [topic_decoder(t) for t in x],
                            blockNumber=quantity_decoder,
                            logIndex=quantity_decoder,
                            transactionIndex=quantity_decoder)
            return [{k: decoders[k](v) for k, v in c.items() if v is not None} for c in changes]

    def call(self, method, *args):
        """ Do the request and returns the result.

        Args:
            method (str): The RPC method.
            args: The encoded arguments expected by the method.
                - Object arguments must be supplied as an dictionary.
                - Quantity arguments must be hex encoded starting with '0x' and
                without left zeros.
                - Data arguments must be hex encoded starting with '0x'
        """
        request = self.protocol.create_request(method, args)
        reply = self.transport.send_message(request.serialize())
        if self.print_communication:
            print json.dumps(json.loads(request.serialize()), indent=2)
            print reply

        jsonrpc_reply = self.protocol.parse_reply(reply)
        if isinstance(jsonrpc_reply, JSONRPCSuccessResponse):
            return jsonrpc_reply.result
        elif isinstance(jsonrpc_reply, JSONRPCErrorResponse):
            raise JSONRPCClientReplyError(jsonrpc_reply.error)
        else:
            raise JSONRPCClientReplyError('Unknown type of JSONRPC reply')

    __call__ = call

    def send_transaction(self, sender, to, value=0, data='', startgas=0,
                         gasprice=10 * denoms.szabo, nonce=None):
        """ Helper to send signed messages.

        This method will use the `privkey` provided in the constructor to
        locally sign the transaction. This requires an extended server
        implementation that accepts the variables v, r, and s.
        """

        if not self.privkey and not sender:
            raise ValueError('Either privkey or sender needs to be supplied.')

        if self.privkey and not sender:
            sender = privtoaddr(self.privkey)

            if nonce is None:
                nonce = self.nonce(sender)
        elif self.privkey:
            if sender != privtoaddr(self.privkey):
                raise ValueError('sender for a different privkey.')

            if nonce is None:
                nonce = self.nonce(sender)
        else:
            if nonce is None:
                nonce = 0

        if not startgas:
            startgas = self.gaslimit() - 1

        tx = Transaction(nonce, gasprice, startgas, to=to, value=value, data=data)

        if self.privkey:
            # add the fields v, r and s
            tx.sign(self.privkey)

        tx_dict = tx.to_dict()

        # rename the fields to match the eth_sendTransaction signature
        tx_dict.pop('hash')
        tx_dict['sender'] = sender
        tx_dict['gasPrice'] = tx_dict.pop('gasprice')
        tx_dict['gas'] = tx_dict.pop('startgas')

        res = self.eth_sendTransaction(**tx_dict)
        assert len(res) in (20, 32)
        return res.encode('hex')

    def eth_sendTransaction(self, nonce=None, sender='', to='', value=0, data='',
                            gasPrice=default_gasprice, gas=default_startgas,
                            v=None, r=None, s=None):
        """ Creates new message call transaction or a contract creation, if the
        data field contains code.

        Note:
            The support for local signing through the variables v,r,s is not
            part of the standard spec, a extended server is required.

        Args:
            from (address): The 20 bytes address the transaction is send from.
            to (address): DATA, 20 Bytes - (optional when creating new
                contract) The address the transaction is directed to.
            gas (int): Gas provided for the transaction execution. It will
                return unused gas.
            gasPrice (int): gasPrice used for each paid gas.
            value (int): Value send with this transaction.
            data (bin): The compiled code of a contract OR the hash of the
                invoked method signature and encoded parameters.
            nonce (int): This allows to overwrite your own pending transactions
                that use the same nonce.
        """

        if to == '' and data.isalnum():
            warnings.warn(
                'Verify that the data parameter is _not_ hex encoded, if this is the case '
                'the data will be double encoded and result in unexpected '
                'behavior.'
            )

        if to == '0' * 40:
            warnings.warn('For contract creating the empty string must be used.')

        json_data = {
            'to': data_encoder(normalize_address(to, allow_blank=True)),
            'value': quantity_encoder(value),
            'gasPrice': quantity_encoder(gasPrice),
            'gas': quantity_encoder(gas),
            'data': data_encoder(data),
        }

        if not sender and not (v and r and s):
            raise ValueError('Either sender or v, r, s needs to be informed.')

        if sender is not None:
            json_data['from'] = address_encoder(sender)

        if v and r and s:
            json_data['v'] = quantity_encoder(v)
            json_data['r'] = quantity_encoder(r)
            json_data['s'] = quantity_encoder(s)

        if nonce is not None:
            json_data['nonce'] = quantity_encoder(nonce)

        res = self.call('eth_sendTransaction', json_data)

        return data_decoder(res)

    def eth_call(self, sender='', to='', value=0, data='',
                 startgas=default_startgas, gasprice=default_gasprice,
                 block_number='latest'):
        """ Executes a new message call immediately without creating a
        transaction on the block chain.

        Args:
            from: The address the transaction is send from.
            to: The address the transaction is directed to.
            gas (int): Gas provided for the transaction execution. eth_call
                consumes zero gas, but this parameter may be needed by some
                executions.
            gasPrice (int): gasPrice used for each paid gas.
            value (int): Integer of the value send with this transaction.
            data (bin): Hash of the method signature and encoded parameters.
                For details see Ethereum Contract ABI.
            block_number: Determines the state of ethereum used in the
                call.
        """

        json_data = dict()

        if sender is not None:
            json_data['from'] = address_encoder(sender)

        if to is not None:
            json_data['to'] = data_encoder(to)

        if value is not None:
            json_data['value'] = quantity_encoder(value)

        if gasprice is not None:
            json_data['gasPrice'] = quantity_encoder(gasprice)

        if startgas is not None:
            json_data['gas'] = quantity_encoder(startgas)

        if data is not None:
            json_data['data'] = data_encoder(data)

        res = self.call('eth_call', json_data, block_number)

        return data_decoder(res)

    def poll(self, transaction_hash, confirmations=None, timeout=None):
        """ Wait until the `transaction_hash` is applied or rejected.
        If timeout is None, this could wait indefinitely!

        Args:
            transaction_hash (hash): Transaction hash that we are waiting for.
            confirmations (int): Number of block confirmations that we will
                wait for.
            timeout (float): Timeout in seconds, raise an Excpetion on
                timeout.
        """
        if transaction_hash.startswith('0x'):
            warnings.warn(
                'transaction_hash seems to be already encoded, this will result '
                'in unexpected behavior'
            )

        if len(transaction_hash) != 32:
            raise ValueError('transaction_hash length must be 32 (it might be hex encode)')

        deadline = None
        if timeout:
            deadline = time.time() + timeout

        transaction_hash = data_encoder(transaction_hash)

        transaction = self.call('eth_getTransactionByHash', transaction_hash)
        while transaction is None or transaction["blockNumber"] is None:
            if deadline and time.time() > deadline:
                raise Exception('timeout when polling for transaction')

            gevent.sleep(.5)
            transaction = self.call('eth_getTransactionByHash', transaction_hash)

        if confirmations is None:
            return

        # this will wait for both APPLIED and REVERTED transactions
        transaction_block = quantity_decoder(transaction['blockNumber'])
        confirmation_block = transaction_block + confirmations

        block_number = self.blocknumber()
        while confirmation_block > block_number:
            if deadline and time.time() > deadline:
                raise Exception('timeout when waiting for confirmation')

            gevent.sleep(.5)
            block_number = self.blocknumber()


class MethodProxy(object):
    """ A callable interface that exposes a contract function. """
    valid_kargs = set(('gasprice', 'startgas', 'value'))

    def __init__(self, sender, contract_address, function_name, translator,
                 call_function, transaction_function):
        self.sender = sender
        self.contract_address = contract_address
        self.function_name = function_name
        self.translator = translator
        self.call_function = call_function
        self.transaction_function = transaction_function

    def transact(self, *args, **kargs):
        assert set(kargs.keys()).issubset(self.valid_kargs)
        data = self.translator.encode(self.function_name, args)

        txhash = self.transaction_function(
            sender=self.sender,
            to=self.contract_address,
            value=kargs.pop('value', 0),
            data=data,
            **kargs
        )

        return txhash

    def call(self, *args, **kargs):
        assert set(kargs.keys()).issubset(self.valid_kargs)
        data = self.translator.encode(self.function_name, args)

        res = self.call_function(
            sender=self.sender,
            to=self.contract_address,
            value=kargs.pop('value', 0),
            data=data,
            **kargs
        )

        if res:
            res = self.translator.decode(self.function_name, res)
            res = res[0] if len(res) == 1 else res
        return res

    def __call__(self, *args, **kargs):
        if self.translator.function_data[self.function_name]['is_constant']:
            return self.call(*args, **kargs)
        else:
            return self.transact(*args, **kargs)


class ContractProxy(object):
    """ Exposes a smart contract as a python object.

    Contract calls can be made directly in this object, all the functions will
    be exposed with the equivalent api and will perform the argument
    translation.
    """

    def __init__(self, sender, abi, address, call_func, transact_func):
        sender = normalize_address(sender)

        self.abi = abi
        self.address = address = normalize_address(address)
        self.translator = ContractTranslator(abi)

        for function_name in self.translator.function_data:
            function_proxy = MethodProxy(
                sender,
                address,
                function_name,
                self.translator,
                call_func,
                transact_func,
            )

            type_argument = self.translator.function_data[function_name]['signature']

            arguments = [
                '{type} {argument}'.format(type=type_, argument=argument)
                for type_, argument in type_argument
            ]
            function_signature = ', '.join(arguments)

            function_proxy.__doc__ = '{function_name}({function_signature})'.format(
                function_name=function_name,
                function_signature=function_signature,
            )

            setattr(self, function_name, function_proxy)

# backwards compatibility
ABIContract = ContractProxy
