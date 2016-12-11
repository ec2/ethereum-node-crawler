import os
import shutil
import tempfile
from uuid import uuid4
import ethereum.keys
from ethereum.slogging import get_logger
from ethereum.utils import decode_hex, remove_0x_head
from devp2p.app import BaseApp
import pytest
from pyethapp.accounts import Account, AccountsService, DEFAULT_COINBASE


# reduce key derivation iterations
ethereum.keys.PBKDF2_CONSTANTS['c'] = 100

log = get_logger('tests.account_service')


@pytest.fixture()
def app(request):
    app = BaseApp(config=dict(accounts=dict(keystore_dir=tempfile.mkdtemp())))
    AccountsService.register_with_app(app)

    def fin():
        # cleanup temporary keystore directory
        assert app.config['accounts']['keystore_dir'].startswith(tempfile.gettempdir())
        shutil.rmtree(app.config['accounts']['keystore_dir'])
        log.debug('cleaned temporary keystore dir', dir=app.config['accounts']['keystore_dir'])
    request.addfinalizer(fin)

    return app


@pytest.fixture()
def privkey():
    return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


@pytest.fixture()
def password():
    return 'secret'


@pytest.fixture()
def uuid():
    return str(uuid4())


@pytest.fixture()
def account(privkey, password, uuid):
    return Account.new(password, privkey, uuid)


def test_empty(app):
    s = app.services.accounts
    assert len(s) == 0
    assert len(s.accounts_with_address) == 0
    assert len(s.unlocked_accounts) == 0
    assert s.accounts == []


def test_add_account(app, account):
    s = app.services.accounts
    assert len(s) == 0
    s.add_account(account, store=False)
    assert len(s) == 1
    assert s.accounts == [account]
    assert s[account.address] == account
    assert s.unlocked_accounts == [account]
    assert s.accounts_with_address == [account]
    assert s.get_by_id(account.uuid) == account


def test_add_locked_account(app, account, password):
    s = app.services.accounts
    account.lock()
    assert account.address is not None
    s.add_account(account, store=False)
    assert s.accounts == [account]
    assert s[account.address] == account
    assert len(s.unlocked_accounts) == 0
    assert s.accounts_with_address == [account]
    assert s.get_by_id(account.uuid) == account
    account.unlock(password)
    assert s.unlocked_accounts == [account]


def test_add_account_without_address(app, account, password):
    s = app.services.accounts
    account.lock()
    address = account.address
    account._address = None
    s.add_account(account, store=False)
    assert s.accounts == [account]
    assert len(s.unlocked_accounts) == 0
    assert len(s.accounts_with_address) == 0
    with pytest.raises(KeyError):
        s[address]
    assert s.get_by_id(account.uuid) == account
    account._address = address  # restore address for following tests
    account.unlock(password)


def test_add_account_twice(app, account):
    s = app.services.accounts
    s.add_account(account, store=False)
    with pytest.raises(ValueError):
        s.add_account(account, store=False)
    assert len(s.accounts) == 1
    uuid = account.uuid
    account.uuid = None
    s.add_account(account, store=False)
    assert len(s) == 2
    assert s.accounts == [account, account]
    assert s[account.address] == account
    assert s.unlocked_accounts == [account, account]
    assert s.accounts_with_address == [account, account]
    account.uuid = uuid


def test_lock_after_adding(app, account, password):
    s = app.services.accounts
    s.add_account(account, store=False)
    assert s.unlocked_accounts == [account]
    account.lock()
    assert len(s.unlocked_accounts) == 0
    account.unlock(password)
    assert s.unlocked_accounts == [account]


def test_find(app, account):
    s = app.services.accounts
    s.add_account(account, store=False)
    assert len(s) == 1
    assert s.find('1') == account
    assert s.find(account.address.encode('hex')) == account
    assert s.find(account.address.encode('hex').upper()) == account
    assert s.find('0x' + account.address.encode('hex')) == account
    assert s.find('0x' + account.address.encode('hex').upper()) == account
    assert s.find(account.uuid) == account
    assert s.find(account.uuid.upper()) == account
    with pytest.raises(ValueError):
        s.find('')
    with pytest.raises(ValueError):
        s.find('aabbcc')
    with pytest.raises(ValueError):
        s.find('xx' * 20)
    with pytest.raises(ValueError):
        s.find('0x' + 'xx' * 20)
    with pytest.raises(KeyError):
        s.find('ff' * 20)
    with pytest.raises(KeyError):
        s.find('0x' + 'ff' * 20)
    with pytest.raises(KeyError):
        s.find(str(uuid4()))


def test_store(app, account):
    s = app.services.accounts
    account.path = os.path.join(app.config['accounts']['keystore_dir'], 'account1')
    s.add_account(account, include_id=True, include_address=True)
    assert os.path.exists(account.path)
    account_reloaded = Account.load(account.path)
    assert account_reloaded.uuid is not None
    assert account_reloaded.address is not None
    assert account_reloaded.uuid == account.uuid
    assert account_reloaded.address == account.address
    assert account_reloaded.privkey is None
    assert account_reloaded.path == account.path
    assert account.privkey is not None
    account.path = None


def test_store_overwrite(app, account):
    s = app.services.accounts
    uuid = account.uuid
    account.uuid = None
    account.path = os.path.join(app.config['accounts']['keystore_dir'], 'account1')
    account2 = Account(account.keystore)
    account2.path = os.path.join(app.config['accounts']['keystore_dir'], 'account2')

    s.add_account(account, store=True)
    with pytest.raises(IOError):
        s.add_account(account, store=True)
    s.add_account(account2, store=True)
    account.uuid = uuid
    account.path = None


def test_store_dir(app, account):
    s = app.services.accounts
    uuid = account.uuid
    account.uuid = None
    paths = [os.path.join(app.config['accounts']['keystore_dir'], p) for p in [
        'some/sub/dir/account1',
        'some/sub/dir/account2',
        'account1',
    ]]

    for path in paths:
        new_account = Account(account.keystore, path=path)
        s.add_account(new_account)
    for path in paths:
        new_account = Account(account.keystore, path=path)
        with pytest.raises(IOError):
            s.add_account(new_account)

    account.uuid = uuid


def test_store_private(app, account, password):
    s = app.services.accounts
    account.path = os.path.join(app.config['accounts']['keystore_dir'], 'account1')
    s.add_account(account, include_id=False, include_address=False)
    account_reloaded = Account.load(account.path)
    assert account_reloaded.address is None
    assert account_reloaded.uuid is None
    account_reloaded.unlock(password)
    assert account_reloaded.address == account.address
    assert account_reloaded.uuid is None
    account.path = None


def test_store_absolute(app, account):
    s = app.services.accounts
    tmpdir = tempfile.mkdtemp()
    account.path = os.path.join(tmpdir, 'account1')
    assert os.path.isabs(account.path)
    s.add_account(account)
    assert os.path.exists(account.path)
    account_reloaded = Account.load(account.path)
    assert account_reloaded.address == account.address
    shutil.rmtree(tmpdir)
    account.path = None


def test_restart_service(app, account, password):
    s = app.services.accounts
    account.path = os.path.join(app.config['accounts']['keystore_dir'], 'account1')
    s.add_account(account)
    app.services.pop('accounts')
    AccountsService.register_with_app(app)
    s = app.services.accounts
    assert len(s) == 1
    reloaded_account = s.accounts[0]
    assert reloaded_account.path == account.path
    assert reloaded_account.address == account.address
    assert reloaded_account.uuid == account.uuid
    assert reloaded_account.privkey is None
    assert reloaded_account.pubkey is None
    reloaded_account.unlock(password)
    assert reloaded_account.privkey == account.privkey
    assert reloaded_account.pubkey == account.pubkey
    account.path = None


def test_account_sorting(app):
    keystore_dummy = {}
    paths = [
        '/absolute/path/b',
        '/absolute/path/c',
        '/absolute/path/letter/e',
        '/absolute/path/letter/d',
        '/letter/f',
        '/absolute/path/a',
        None
    ]
    paths_sorted = sorted(paths)

    s = app.services.accounts
    for path in paths:
        s.add_account(Account(keystore_dummy, path=path), store=False)

    assert [account.path for account in s.accounts] == paths_sorted
    assert [s.find(str(i)).path for i in xrange(1, len(paths) + 1)] == paths_sorted


def test_update(app, account, password):
    s = app.services.accounts
    path = os.path.join(app.config['accounts']['keystore_dir'], 'update_test')
    address = account.address
    privkey = account.privkey
    pubkey = account.pubkey
    uuid = account.uuid

    with pytest.raises(ValueError):
        s.update_account(account, 'pw2')
    s.add_account(account, store=False)
    with pytest.raises(ValueError):
        s.update_account(account, 'pw2')
    s.accounts.remove(account)
    account.path = path
    s.add_account(account, store=True)
    account.lock()
    with pytest.raises(ValueError):
        s.update_account(account, 'pw2')
    account.unlock(password)
    s.update_account(account, 'pw2')

    assert account.path == path
    assert account.address == address
    assert account.privkey == privkey
    assert account.pubkey == pubkey
    assert account.uuid == uuid
    assert not account.locked
    assert account in s.accounts

    account.lock()
    with pytest.raises(ValueError):
        account.unlock(password)
    account.unlock('pw2')
    assert not account.locked

    assert os.listdir(app.config['accounts']['keystore_dir']) == ['update_test']

    files = ['update_test~' + str(i) for i in xrange(20)]
    files.append('update_test~')
    for filename in files:
        # touch files
        open(os.path.join(app.config['accounts']['keystore_dir'], filename), 'w').close()
    s.update_account(account, 'pw3')
    assert set(os.listdir(app.config['accounts']['keystore_dir'])) == set(files + ['update_test'])
    account.path = None


def test_coinbase(app, account):
    s = app.services.accounts
    # coinbase not configured at all
    assert s.coinbase == DEFAULT_COINBASE

    # coinbase from first account
    s.add_account(account, store=False)
    app.config['accounts']['must_include_coinbase'] = True
    assert s.coinbase == account.address
    app.config['accounts']['must_include_coinbase'] = False
    assert s.coinbase == account.address

    # coinbase configured
    app.config['pow'] = {'coinbase_hex': account.address.encode('hex')}
    app.config['accounts']['must_include_coinbase'] = True
    assert s.coinbase == account.address
    app.config['accounts']['must_include_coinbase'] = False
    assert s.coinbase == account.address

    for invalid_coinbase in [123, '\x00' * 20, '\x00' * 40, '', 'aabbcc', 'aa' * 19, 'ff' * 21]:
        app.config['pow'] = {'coinbase_hex': invalid_coinbase}
        app.config['accounts']['must_include_coinbase'] = False
        with pytest.raises(ValueError):
            s.coinbase
        app.config['accounts']['must_include_coinbase'] = True
        with pytest.raises(ValueError):
            s.coinbase
    for valid_coinbase in ['00' * 20, 'ff' * 20, '0x' + 'aa' * 20]:
        app.config['pow'] = {'coinbase_hex': valid_coinbase}
        app.config['accounts']['must_include_coinbase'] = False
        assert s.coinbase == decode_hex(remove_0x_head(valid_coinbase))
        app.config['accounts']['must_include_coinbase'] = True
        with pytest.raises(ValueError):
            s.coinbase
