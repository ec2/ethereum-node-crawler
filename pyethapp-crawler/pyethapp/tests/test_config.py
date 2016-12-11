from devp2p.peermanager import PeerManager
from devp2p.discovery import NodeDiscovery
from devp2p.app import BaseApp
from py._path.local import LocalPath
from pyethapp.eth_service import ChainService
from pyethapp.jsonrpc import JSONRPCServer
from pyethapp.db_service import DBService
from pyethapp import config
import tempfile
import copy
import pytest


base_services = [DBService, NodeDiscovery, PeerManager, ChainService, JSONRPCServer]


def test_default_config():
    conf = config.get_default_config([BaseApp] + base_services)
    assert 'p2p' in conf
    assert 'app' not in conf


def test_save_load_config():
    conf = config.get_default_config([BaseApp] + base_services)
    assert conf
    garbage_conf = tempfile.mktemp()  # do not use default paths in tests!

    # from fn or base path
    config.write_config(conf, path=garbage_conf)
    conf2 = config.load_config(path=garbage_conf)
    print 'b', conf
    print 'a', conf2
    assert conf == conf2

    path = tempfile.mktemp()
    assert path
    config.write_config(conf, path=path)
    conf3 = config.load_config(path=path)
    assert conf == conf3


def test_update_config():
    conf = config.get_default_config([BaseApp] + base_services)
    conf_copy = copy.deepcopy(conf)
    conf2 = config.update_config_with_defaults(conf, dict(p2p=dict(new_key=1)))
    assert conf is conf2
    assert conf == conf2
    assert conf_copy != conf


def test_set_config_param():
    conf = config.get_default_config([BaseApp] + base_services)
    assert conf['p2p']['min_peers']
    conf = config.set_config_param(conf, 'p2p.min_peers=3')  # strict
    assert conf['p2p']['min_peers'] == 3
    with pytest.raises(KeyError):
        conf = config.set_config_param(conf, 'non.existent=1')
    conf = config.set_config_param(conf, 'non.existent=1', strict=False)
    assert conf['non']['existent'] == 1


def test_setup_data_dir(tmpdir):
    data_dir = tmpdir.join('data')
    config.setup_data_dir(str(data_dir))

    assert data_dir.join(config.CONFIG_FILE_NAME).exists()


def test_setup_data_dir_existing_empty(tmpdir):
    data_dir = tmpdir.join('data').ensure_dir()
    config.setup_data_dir(str(data_dir))

    assert data_dir.join(config.CONFIG_FILE_NAME).exists()


def test_setup_data_dir_existing_config(tmpdir):
    data_dir = tmpdir.join('data')
    data_dir.ensure('config.yaml')
    config.setup_data_dir(str(data_dir))

    assert data_dir.join(config.CONFIG_FILE_NAME).exists()


def test_dump_config_does_not_leak_privkey(capsys):
    conf = config.get_default_config([BaseApp] + base_services)
    SECRET = "thisshouldnotbedumpedincleartext"
    conf['accounts'] = {}
    conf['accounts']['privkeys_hex'] = [SECRET]
    conf['node'] = {}
    conf['node']['privkey_hex'] = SECRET

    config.dump_config(conf)

    output = capsys.readouterr()[0]
    assert 'node' in output  # sanity check
    assert SECRET not in output
