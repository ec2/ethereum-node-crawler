import signal
import warnings
from collections import Mapping
import os

import click
import ethereum
import gevent
from IPython.core import ultratb
from ethereum.blocks import Block, genesis
from devp2p.service import BaseService
import rlp
import sys
from ethereum import slogging
from ethereum.slogging import bcolors
import types


slogging.set_level('db', 'debug')
log = slogging.get_logger('db')


def load_contrib_services(config):  # FIXME
    # load contrib services
    config_directory = config['data_dir']
    contrib_directory = os.path.join(config_directory, 'contrib')  # change to pyethapp/contrib
    contrib_modules = []
    if not os.path.exists(contrib_directory):
        log.info('No contrib directory found, so not loading any user services')
        return []
    x = os.getcwd()
    os.chdir(config_directory)
    for filename in os.listdir(contrib_directory):
        if filename.endswith('.py'):
            print filename
            try:
                __import__(filename[:-3])
                library_conflict = True
            except:
                library_conflict = False
            if library_conflict:
                raise Exception("Library conflict: please rename " + filename + " in contribs")
            sys.path.append(contrib_directory)
            contrib_modules.append(__import__(filename[:-3]))
            sys.path.pop()
    contrib_services = []
    for module in contrib_modules:
        print 'm', module, dir(module)
        on_start, on_block = None, None
        for variable in dir(module):
            cls = getattr(module, variable)
            if isinstance(cls, (type, types.ClassType)):
                if issubclass(cls, BaseService) and cls != BaseService:
                    contrib_services.append(cls)
            if variable == 'on_block':
                on_block = getattr(module, variable)
            if variable == 'on_start':
                on_start = getattr(module, variable)
        if on_start or on_block:
            contrib_services.append(on_block_callback_service_factory(on_start, on_block))
    log.info('Loaded contrib services', services=contrib_services)
    return contrib_services


def on_block_callback_service_factory(on_start, on_block):

    class _OnBlockCallbackService(BaseService):

        name = 'onblockservice%d' % on_block_callback_service_factory.created

        def start(self):
            super(_OnBlockCallbackService, self).start()
            self.app.services.chain.on_new_head_cbs.append(self.cb)
            if on_start:
                on_start(self.app)

        def cb(self, blk):
            if on_block:
                on_block(blk)
    on_block_callback_service_factory.created += 1
    return _OnBlockCallbackService

on_block_callback_service_factory.created = 0


def load_block_tests(data, db):
    """Load blocks from json file.

    :param data: the data from the json file as dictionary
    :param db: the db in which the blocks will be stored
    :raises: :exc:`ValueError` if the file contains invalid blocks
    :raises: :exc:`KeyError` if the file is missing required data fields
    :returns: a list of blocks in an ephem db
    """
    scanners = ethereum.utils.scanners
    initial_alloc = {}
    for address, acct_state in data['pre'].items():
        address = ethereum.utils.decode_hex(address)
        balance = scanners['int256b'](acct_state['balance'][2:])
        nonce = scanners['int256b'](acct_state['nonce'][2:])
        initial_alloc[address] = {
            'balance': balance,
            'code': acct_state['code'],
            'nonce': nonce,
            'storage': acct_state['storage']
        }
    env = ethereum.config.Env(db=db)
    genesis(env, start_alloc=initial_alloc)  # builds the state trie
    genesis_block = rlp.decode(ethereum.utils.decode_hex(data['genesisRLP'][2:]), Block, env=env)
    blocks = {genesis_block.hash: genesis_block}
    for blk in data['blocks']:
        rlpdata = ethereum.utils.decode_hex(blk['rlp'][2:])
        assert ethereum.utils.decode_hex(blk['blockHeader']['parentHash']) in blocks
        parent = blocks[ethereum.utils.decode_hex(blk['blockHeader']['parentHash'])]
        block = rlp.decode(rlpdata, Block, parent=parent, env=env)
        blocks[block.hash] = block
    return sorted(blocks.values(), key=lambda b: b.number)


def merge_dict(dest, source):
    stack = [(dest, source)]
    while stack:
        curr_dest, curr_source = stack.pop()
        for key in curr_source:
            if key not in curr_dest:
                curr_dest[key] = curr_source[key]
            else:
                if isinstance(curr_source[key], Mapping):
                    if isinstance(curr_dest[key], Mapping):
                        stack.append((curr_dest[key], curr_source[key]))
                    else:
                        raise ValueError('Incompatible types during merge: {} and {}'.format(
                            type(curr_source[key]),
                            type(curr_dest[key])
                        ))
                else:
                    curr_dest[key] = curr_source[key]
    return dest


class FallbackChoice(click.Choice):
    def __init__(self, choices, fallbacks, fallback_warning):
        super(FallbackChoice, self).__init__(choices)
        self.fallbacks = fallbacks
        self.fallback_warning = fallback_warning

    def convert(self, value, param, ctx):
        if value in self.fallbacks:
            warnings.warn(self.fallback_warning)
            value = self.fallbacks[value]
        return super(FallbackChoice, self).convert(value, param, ctx)


def enable_greenlet_debugger():
    def _print_exception(self, context, type_, value, traceback):
        ultratb.VerboseTB(call_pdb=True)(type_, value, traceback)
        resp = raw_input(
            "{c.OKGREEN}Debugger exited. "
            "{c.OKBLUE}Do you want to quit pyethapp?{c.ENDC} [{c.BOLD}Y{c.ENDC}/n] ".format(
                c=bcolors
            )
        ).strip().lower()
        if not resp or resp.startswith("y"):
            os.kill(os.getpid(), signal.SIGTERM)

    gevent.get_hub().__class__.print_exception = _print_exception
