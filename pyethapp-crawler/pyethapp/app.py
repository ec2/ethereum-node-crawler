# -*- coding: utf8 -*-
import copy
import json
import os
import signal
import sys
from logging import StreamHandler
from uuid import uuid4

import click
import ethereum.slogging as slogging
import gevent
import rlp
from click import BadParameter
from devp2p.app import BaseApp
from devp2p.discovery import NodeDiscovery
from devp2p.peermanager import PeerManager
from devp2p.service import BaseService
from ethereum import blocks
from ethereum.blocks import Block
from gevent.event import Event

import config as konfig
import eth_protocol
import utils
from accounts import AccountsService, Account
from console_service import Console
from db_service import DBService
from eth_service import ChainService
from jsonrpc import JSONRPCServer, IPCRPCServer
from pow_service import PoWService
from pyethapp import __version__
from pyethapp.profiles import PROFILES, DEFAULT_PROFILE
from pyethapp.utils import merge_dict, load_contrib_services, FallbackChoice, enable_greenlet_debugger


log = slogging.get_logger('app')

services = [DBService, AccountsService, NodeDiscovery, PeerManager, ChainService, PoWService,
            JSONRPCServer, IPCRPCServer, Console]


class EthApp(BaseApp):
    client_name = 'pyethapp'
    client_version = '%s/%s/%s' % (__version__, sys.platform,
                                   'py%d.%d.%d' % sys.version_info[:3])
    client_version_string = '%s/v%s' % (client_name, client_version)
    start_console = False
    default_config = dict(BaseApp.default_config)
    default_config['client_version_string'] = client_version_string
    default_config['post_app_start_callback'] = None
    script_globals = {}


# TODO: Remove `profile` fallbacks in 1.4 or so
# Separators should be underscore!
@click.group(help='Welcome to {} {}'.format(EthApp.client_name, EthApp.client_version))
@click.option('--profile', type=FallbackChoice(
                  PROFILES.keys(),
                  {'frontier': 'livenet', 'morden': 'testnet'},
                  "PyEthApp's configuration profiles have been renamed to "
                  "'livenet' and 'testnet'. The previous values 'frontier' and "
                  "'morden' will be removed in a future update."),
              default=DEFAULT_PROFILE, help="Configuration profile.", show_default=True)
@click.option('alt_config', '--Config', '-C', type=str, callback=konfig.validate_alt_config_file,
              help='Alternative config file')
@click.option('config_values', '-c', multiple=True, type=str,
              help='Single configuration parameters (<param>=<value>)')
@click.option('alt_data_dir', '-d', '--data-dir', multiple=False, type=str,
              help='data directory', default=konfig.default_data_dir, show_default=True)
@click.option('-l', '--log_config', multiple=False, type=str, default=":info",
              help='log_config string: e.g. ":info,eth:debug', show_default=True)
@click.option('--log-json/--log-no-json', default=False,
              help='log as structured json output')
@click.option('--log-file', type=click.Path(dir_okay=False, writable=True, resolve_path=True),
              help="Log to file instead of stderr.")
@click.option('-b', '--bootstrap_node', multiple=False, type=str,
              help='single bootstrap_node as enode://pubkey@host:port')
@click.option('-m', '--mining_pct', multiple=False, type=int, default=0,
              help='pct cpu used for mining')
@click.option('--unlock', multiple=True, type=str,
              help='Unlock an account (prompts for password)')
@click.option('--password', type=click.File(), help='path to a password file')
@click.pass_context
def app(ctx, profile, alt_config, config_values, alt_data_dir, log_config, bootstrap_node, log_json,
        mining_pct, unlock, password, log_file):
    # configure logging
    slogging.configure(log_config, log_json=log_json, log_file=log_file)

    # data dir default or from cli option
    alt_data_dir = os.path.expanduser(alt_data_dir)
    data_dir = alt_data_dir or konfig.default_data_dir
    konfig.setup_data_dir(data_dir)  # if not available, sets up data_dir and required config
    log.info('using data in', path=data_dir)

    # prepare configuration
    # config files only contain required config (privkeys) and config different from the default
    if alt_config:  # specified config file
        config = konfig.load_config(alt_config)
        if not config:
            log.warning('empty config given. default config values will be used')
    else:  # load config from default or set data_dir
        config = konfig.load_config(data_dir)

    config['data_dir'] = data_dir

    # Store custom genesis to restore if overridden by profile value
    genesis_from_config_file = config.get('eth', {}).get('genesis')

    # Store custom bootstrap_nodes to restore them overridden by profile value
    bootstrap_nodes_from_config_file = config.get('discovery', {}).get('bootstrap_nodes')

    # add default config
    konfig.update_config_with_defaults(config, konfig.get_default_config([EthApp] + services))

    konfig.update_config_with_defaults(config, {'eth': {'block': blocks.default_config}})

    # Set config values based on profile selection
    merge_dict(config, PROFILES[profile])

    if genesis_from_config_file:
        # Fixed genesis_hash taken from profile must be deleted as custom genesis loaded
        del config['eth']['genesis_hash']
        config['eth']['genesis'] = genesis_from_config_file

    if bootstrap_nodes_from_config_file:
        # Fixed bootstrap_nodes taken from profile must be deleted as custom bootstrap_nodes loaded
        del config['discovery']['bootstrap_nodes']
        config['discovery']['bootstrap_nodes'] = bootstrap_nodes_from_config_file

    pre_cmd_line_config_genesis = config.get('eth', {}).get('genesis')
    # override values with values from cmd line
    for config_value in config_values:
        try:
            konfig.set_config_param(config, config_value)
        except ValueError:
            raise BadParameter('Config parameter must be of the form "a.b.c=d" where "a.b.c" '
                               'specifies the parameter to set and d is a valid yaml value '
                               '(example: "-c jsonrpc.port=5000")')

    if pre_cmd_line_config_genesis != config.get('eth', {}).get('genesis'):
        # Fixed genesis_hash taked from profile must be deleted as custom genesis loaded
        if 'genesis_hash' in config['eth']:
            del config['eth']['genesis_hash']

    # Load genesis config
    konfig.update_config_from_genesis_json(config,
                                           genesis_json_filename_or_dict=config['eth']['genesis'])
    if bootstrap_node:
        config['discovery']['bootstrap_nodes'] = [bytes(bootstrap_node)]
    if mining_pct > 0:
        config['pow']['activated'] = True
        config['pow']['cpu_pct'] = int(min(100, mining_pct))
    if not config.get('pow', {}).get('activated'):
        config['deactivated_services'].append(PoWService.name)

    ctx.obj = {'config': config,
               'unlock': unlock,
               'password': password.read().rstrip() if password else None,
               'log_file': log_file}
    assert (password and ctx.obj['password'] is not None and len(
        ctx.obj['password'])) or not password, "empty password file"


@app.command()
@click.option('--dev/--nodev', default=False,
              help='Drop into interactive debugger on unhandled exceptions.')
@click.option('--nodial/--dial',  default=False, help='Do not dial nodes.')
@click.option('--fake/--nofake',  default=False, help='Fake genesis difficulty.')
@click.option('--console',  is_flag=True, help='Immediately drop into interactive console.')
@click.pass_context
def run(ctx, dev, nodial, fake, console):
    """Start the client ( --dev to stop on error)"""
    config = ctx.obj['config']
    if nodial:
        # config['deactivated_services'].append(PeerManager.name)
        # config['deactivated_services'].append(NodeDiscovery.name)
        config['discovery']['bootstrap_nodes'] = []
        config['discovery']['listen_port'] = 29873
        config['p2p']['listen_port'] = 29873
        config['p2p']['min_peers'] = 0

    if fake:
        from ethereum import blocks
        blocks.GENESIS_DIFFICULTY = 1024
        blocks.BLOCK_DIFF_FACTOR = 16
        blocks.MIN_GAS_LIMIT = blocks.default_config['GENESIS_GAS_LIMIT'] / 2
        config['eth']['block']['GENESIS_DIFFICULTY'] = 1024
        config['eth']['block']['BLOCK_DIFF_FACTOR'] = 16

    # create app
    app = EthApp(config)

    # development mode
    if dev:
        enable_greenlet_debugger()
        try:
            config['client_version'] += '/' + os.getlogin()
        except:
            log.warn("can't get and add login name to client_version")
            pass

    # dump config
    dump_config(config)

    # init and unlock accounts first to check coinbase
    if AccountsService in services:
        AccountsService.register_with_app(app)
        unlock_accounts(ctx.obj['unlock'], app.services.accounts, password=ctx.obj['password'])
        try:
            app.services.accounts.coinbase
        except ValueError as e:
            log.fatal('invalid coinbase', coinbase=config.get('pow', {}).get('coinbase_hex'),
                      error=e.message)
            sys.exit()

    app.start_console = console

    # register services
    contrib_services = load_contrib_services(config)

    for service in services + contrib_services:
        assert issubclass(service, BaseService)
        if service.name not in app.config['deactivated_services'] + [AccountsService.name]:
            assert service.name not in app.services
            service.register_with_app(app)
            assert hasattr(app.services, service.name)

    # start app
    log.info('starting')
    app.start()

    if ctx.obj['log_file']:
        log.info("Logging to file %s", ctx.obj['log_file'])
        # User requested file logging - remove stderr handler
        root_logger = slogging.getLogger()
        for hndlr in root_logger.handlers:
            if isinstance(hndlr, StreamHandler) and hndlr.stream == sys.stderr:
                root_logger.removeHandler(hndlr)
                break

    if config['post_app_start_callback'] is not None:
        config['post_app_start_callback'](app)

    # wait for interrupt
    evt = Event()
    gevent.signal(signal.SIGQUIT, evt.set)
    gevent.signal(signal.SIGTERM, evt.set)
    evt.wait()

    # finally stop
    app.stop()


def dump_config(config):
    cfg = copy.deepcopy(config)
    alloc = cfg.get('eth', {}).get('block', {}).get('GENESIS_INITIAL_ALLOC', {})
    if len(alloc) > 100:
        log.info('omitting reporting of %d accounts in genesis' % len(alloc))
        del cfg['eth']['block']['GENESIS_INITIAL_ALLOC']
    konfig.dump_config(cfg)


@app.command()
@click.pass_context
def config(ctx):
    """Show the config"""
    dump_config(ctx.obj['config'])


@app.command()
@click.argument('file', type=click.File(), required=True)
@click.argument('name', type=str, required=True)
@click.pass_context
def blocktest(ctx, file, name):
    """Start after importing blocks from a file.

    In order to prevent replacement of the local test chain by the main chain from the network, the
    peermanager, if registered, is stopped before importing any blocks.

    Also, for block tests an in memory database is used. Thus, a already persisting chain stays in
    place.
    """
    app = EthApp(ctx.obj['config'])
    app.config['db']['implementation'] = 'EphemDB'

    # register services
    for service in services:
        assert issubclass(service, BaseService)
        if service.name not in app.config['deactivated_services']:
            assert service.name not in app.services
            service.register_with_app(app)
            assert hasattr(app.services, service.name)

    if ChainService.name not in app.services:
        log.fatal('No chainmanager registered')
        ctx.abort()
    if DBService.name not in app.services:
        log.fatal('No db registered')
        ctx.abort()

    log.info('loading block file', path=file.name)
    try:
        data = json.load(file)
    except ValueError:
        log.fatal('Invalid JSON file')
    if name not in data:
        log.fatal('Name not found in file')
        ctx.abort()
    try:
        blocks = utils.load_block_tests(data.values()[0], app.services.chain.chain.db)
    except ValueError:
        log.fatal('Invalid blocks encountered')
        ctx.abort()

    # start app
    app.start()
    if 'peermanager' in app.services:
        app.services.peermanager.stop()

    log.info('building blockchain')
    Block.is_genesis = lambda self: self.number == 0
    app.services.chain.chain._initialize_blockchain(genesis=blocks[0])
    for block in blocks[1:]:
        app.services.chain.chain.add_block(block)

    # wait for interrupt
    evt = Event()
    gevent.signal(signal.SIGQUIT, evt.set)
    gevent.signal(signal.SIGTERM, evt.set)
    gevent.signal(signal.SIGINT, evt.set)
    evt.wait()

    # finally stop
    app.stop()


@app.command('export')
@click.option('--from', 'from_', type=int, help='Number of the first block (default: genesis)')
@click.option('--to', type=int, help='Number of the last block (default: latest)')
@click.argument('file', type=click.File('ab'))
@click.pass_context
def export_blocks(ctx, from_, to, file):
    """Export the blockchain to FILE.

    The chain will be stored in binary format, i.e. as a concatenated list of RLP encoded blocks,
    starting with the earliest block.

    If the file already exists, the additional blocks are appended. Otherwise, a new file is
    created.

    Use - to write to stdout.
    """
    app = EthApp(ctx.obj['config'])
    DBService.register_with_app(app)
    AccountsService.register_with_app(app)
    ChainService.register_with_app(app)

    if from_ is None:
        from_ = 0
    head_number = app.services.chain.chain.head.number
    if to is None:
        to = head_number
    if from_ < 0:
        log.fatal('block numbers must not be negative')
        sys.exit(1)
    if to < from_:
        log.fatal('"to" block must be newer than "from" block')
        sys.exit(1)
    if to > head_number:
        log.fatal('"to" block not known (current head: {})'.format(head_number))
        sys.exit(1)

    log.info('Starting export')
    for n in xrange(from_, to + 1):
        log.debug('Exporting block {}'.format(n))
        if (n - from_) % 50000 == 0:
            log.info('Exporting block {} to {}'.format(n, min(n + 50000, to)))
        block_hash = app.services.chain.chain.index.get_block_by_number(n)
        # bypass slow block decoding by directly accessing db
        block_rlp = app.services.db.get(block_hash)
        file.write(block_rlp)
    log.info('Export complete')


@app.command('import')
@click.argument('file', type=click.File('rb'))
@click.pass_context
def import_blocks(ctx, file):
    """Import blocks from FILE.

    Blocks are expected to be in binary format, i.e. as a concatenated list of RLP encoded blocks.

    Blocks are imported sequentially. If a block can not be imported (e.g. because it is badly
    encoded, it is in the chain already or its parent is not in the chain) it will be ignored, but
    the process will continue. Sole exception: If neither the first block nor its parent is known,
    importing will end right away.

    Use - to read from stdin.
    """
    app = EthApp(ctx.obj['config'])
    DBService.register_with_app(app)
    AccountsService.register_with_app(app)
    ChainService.register_with_app(app)
    chain = app.services.chain
    assert chain.block_queue.empty()

    data = file.read()
    app.start()

    def blocks():
        """Generator for blocks encoded in `data`."""
        i = 0
        while i < len(data):
            try:
                block_data, next_i = rlp.codec.consume_item(data, i)
            except rlp.DecodingError:
                log.fatal('invalid RLP encoding', byte_index=i)
                sys.exit(1)  # have to abort as we don't know where to continue
            try:
                if not isinstance(block_data, list) or len(block_data) != 3:
                    raise rlp.DeserializationError('', block_data)
                yield eth_protocol.TransientBlock(block_data)
            except (IndexError, rlp.DeserializationError):
                log.warning('not a valid block', byte_index=i)  # we can still continue
                yield None
            i = next_i

    log.info('importing blocks')
    # check if it makes sense to go through all blocks
    first_block = next(blocks())
    if first_block is None:
        log.fatal('first block invalid')
        sys.exit(1)
    if not (chain.knows_block(first_block.header.hash) or
            chain.knows_block(first_block.header.prevhash)):
        log.fatal('unlinked chains', newest_known_block=chain.chain.head.number,
                  first_unknown_block=first_block.header.number)
        sys.exit(1)

    # import all blocks
    for n, block in enumerate(blocks()):
        if block is None:
            log.warning('skipping block', number_in_file=n)
            continue
        log.debug('adding block to queue', number_in_file=n, number_in_chain=block.header.number)
        app.services.chain.add_block(block, None)  # None for proto

    # let block processing finish
    while not app.services.chain.block_queue.empty():
        gevent.sleep()
    app.stop()
    log.info('import finished', head_number=app.services.chain.chain.head.number)


@app.group()
@click.pass_context
def account(ctx):
    """Manage accounts.

    For accounts to be accessible by pyethapp, their keys must be stored in the keystore directory.
    Its path can be configured through "accounts.keystore_dir".
    """
    app = EthApp(ctx.obj['config'])
    ctx.obj['app'] = app
    AccountsService.register_with_app(app)
    unlock_accounts(ctx.obj['unlock'], app.services.accounts, password=ctx.obj['password'])


@account.command('new')
@click.option('--uuid', '-i', help='equip the account with a random UUID', is_flag=True)
@click.pass_context
def new_account(ctx, uuid):
    """Create a new account.

    This will generate a random private key and store it in encrypted form in the keystore
    directory. You are prompted for the password that is employed (if no password file is
    specified). If desired the private key can be associated with a random UUID (version 4) using
    the --uuid flag.
    """
    app = ctx.obj['app']
    if uuid:
        id_ = str(uuid4())
    else:
        id_ = None
    password = ctx.obj['password']
    if password is None:
        password = click.prompt('Password to encrypt private key', default='', hide_input=True,
                                confirmation_prompt=True, show_default=False)
    account = Account.new(password, uuid=id_)
    account.path = os.path.join(app.services.accounts.keystore_dir, account.address.encode('hex'))
    try:
        app.services.accounts.add_account(account)
    except IOError:
        click.echo('Could not write keystore file. Make sure you have write permission in the '
                   'configured directory and check the log for further information.')
        sys.exit(1)
    else:
        click.echo('Account creation successful')
        click.echo('  Address: ' + account.address.encode('hex'))
        click.echo('       Id: ' + str(account.uuid))


@account.command('list')
@click.pass_context
def list_accounts(ctx):
    """List accounts with addresses and ids.

    This prints a table of all accounts, numbered consecutively, along with their addresses and
    ids. Note that some accounts do not have an id, and some addresses might be hidden (i.e. are
    not present in the keystore file). In the latter case, you have to unlock the accounts (e.g.
    via "pyethapp --unlock <account> account list") to display the address anyway.
    """
    accounts = ctx.obj['app'].services.accounts
    if len(accounts) == 0:
        click.echo('no accounts found')
    else:
        fmt = '{i:>4} {address:<40} {id:<36} {locked:<1}'
        click.echo('     {address:<40} {id:<36} {locked}'.format(address='Address (if known)',
                                                                 id='Id (if any)',
                                                                 locked='Locked'))
        for i, account in enumerate(accounts):
            click.echo(fmt.format(i='#' + str(i + 1),
                                  address=(account.address or '').encode('hex'),
                                  id=account.uuid or '',
                                  locked='yes' if account.locked else 'no'))


@account.command('import')
@click.argument('f', type=click.File(), metavar='FILE')
@click.option('--uuid', '-i', help='equip the new account with a random UUID', is_flag=True)
@click.pass_context
def import_account(ctx, f, uuid):
    """Import a private key from FILE.

    FILE is the path to the file in which the private key is stored. The key is assumed to be hex
    encoded, surrounding whitespace is stripped. A new account is created for the private key, as
    if it was created with "pyethapp account new", and stored in the keystore directory. You will
    be prompted for a password to encrypt the key (if no password file is specified). If desired a
    random UUID (version 4) can be generated using the --uuid flag in order to identify the new
    account later.
    """
    app = ctx.obj['app']
    if uuid:
        id_ = str(uuid4())
    else:
        id_ = None
    privkey_hex = f.read()
    try:
        privkey = privkey_hex.strip().decode('hex')
    except TypeError:
        click.echo('Could not decode private key from file (should be hex encoded)')
        sys.exit(1)
    password = ctx.obj['password']
    if password is None:
        password = click.prompt('Password to encrypt private key', default='', hide_input=True,
                                confirmation_prompt=True, show_default=False)
    account = Account.new(password, privkey, uuid=id_)
    account.path = os.path.join(app.services.accounts.keystore_dir, account.address.encode('hex'))
    try:
        app.services.accounts.add_account(account)
    except IOError:
        click.echo('Could not write keystore file. Make sure you have write permission in the '
                   'configured directory and check the log for further information.')
        sys.exit(1)
    else:
        click.echo('Account creation successful')
        click.echo('  Address: ' + account.address.encode('hex'))
        click.echo('       Id: ' + str(account.uuid))


@account.command('update')
@click.argument('account', type=str)
@click.pass_context
def update_account(ctx, account):
    """
    Change the password of an account.

    ACCOUNT identifies the account: It can be one of the following: an address, a uuid, or a
    number corresponding to an entry in "pyethapp account list" (one based).

    "update" first prompts for the current password to unlock the account. Next, the new password
    must be entered.

    The password replacement procedure backups the original keystore file in the keystore
    directory, creates the new file, and finally deletes the backup. If something goes wrong, an
    attempt will be made to restore the keystore file from the backup. In the event that this does
    not work, it is possible to recover from the backup manually by simply renaming it. The backup
    shares the same name as the original file, but with an appended "~" plus a number if necessary
    to avoid name clashes.

    As this command tampers with your keystore directory, it is advisable to perform a manual
    backup in advance.

    If a password is provided via the "--password" option (on the "pyethapp" base command), it will
    be used to unlock the account, but not as the new password (as distinguished from
    "pyethapp account new").
    """
    app = ctx.obj['app']
    unlock_accounts([account], app.services.accounts, password=ctx.obj['password'])
    old_account = app.services.accounts.find(account)
    if old_account.locked:
        click.echo('Account needs to be unlocked in order to update its password')
        sys.exit(1)

    click.echo('Updating account')
    click.echo('Address: {}'.format(old_account.address.encode('hex')))
    click.echo('     Id: {}'.format(old_account.uuid))

    new_password = click.prompt('New password', default='', hide_input=True,
                                confirmation_prompt=True, show_default=False)

    try:
        app.services.accounts.update_account(old_account, new_password)
    except:
        click.echo('Account update failed. Make sure that the keystore file has been restored '
                   'correctly (e.g. with "pyethapp --unlock <acct> account list"). If not, look '
                   'for automatic backup files in the keystore directory (suffix "~" or '
                   '"~<number>"). Check the log for further information.')
        raise
    click.echo('Account update successful')


def unlock_accounts(account_ids, account_service, max_attempts=3, password=None):
    """Unlock a list of accounts, prompting for passwords one by one if not given.

    If a password is specified, it will be used to unlock all accounts. If not, the user is
    prompted for one password per account.

    If an account can not be identified or unlocked, an error message is logged and the program
    exits.

    :param accounts: a list of account identifiers accepted by :meth:`AccountsService.find`
    :param account_service: the account service managing the given accounts
    :param max_attempts: maximum number of attempts per account before the unlocking process is
                         aborted (>= 1), or `None` to allow an arbitrary number of tries
    :param password: optional password which will be used to unlock the accounts
    """
    accounts = []
    for account_id in account_ids:
        try:
            account = account_service.find(account_id)
        except KeyError:
            log.fatal('could not find account', identifier=account_id)
            sys.exit(1)
        accounts.append(account)

    if password is not None:
        for identifier, account in zip(account_ids, accounts):
            try:
                account.unlock(password)
            except ValueError:
                log.fatal('Could not unlock account with password from file',
                          account_id=identifier)
                sys.exit(1)
        return

    max_attempts_str = str(max_attempts) if max_attempts else 'oo'
    attempt_fmt = '(attempt {{attempt}}/{})'.format(max_attempts_str)
    first_attempt_fmt = 'Password for account {id} ' + attempt_fmt
    further_attempts_fmt = 'Wrong password. Please try again ' + attempt_fmt

    for identifier, account in zip(account_ids, accounts):
        attempt = 1
        pw = click.prompt(first_attempt_fmt.format(id=identifier, attempt=1), hide_input=True,
                          default='', show_default=False)
        while True:
            attempt += 1
            try:
                account.unlock(pw)
            except ValueError:
                if max_attempts and attempt > max_attempts:
                    log.fatal('Too many unlock attempts', attempts=attempt, account_id=identifier)
                    sys.exit(1)
                else:
                    pw = click.prompt(further_attempts_fmt.format(attempt=attempt),
                                      hide_input=True, default='', show_default=False)
            else:
                break
        assert not account.locked


if __name__ == '__main__':
    #  python app.py 2>&1 | less +F
    app()
