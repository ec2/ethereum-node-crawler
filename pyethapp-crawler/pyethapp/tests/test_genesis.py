from pprint import pprint
import pytest
from ethereum import blocks
from ethereum.db import DB
from ethereum.config import Env
from pyethapp.utils import merge_dict
from pyethapp.config import update_config_from_genesis_json
import pyethapp.config as konfig
from pyethapp.profiles import PROFILES


def test_genesis_config():
    "test setting genesis alloc using the config"
    alloc = {'1' * 40: {'wei': 1},  # wei
             '2' * 40: {'balance': 2},  # balance
             '3' * 20: {'balance': 3},  # 20 bytes
             }
    config = dict(eth=dict(genesis=dict(alloc=alloc)))
    konfig.update_config_with_defaults(config, {'eth': {'block': blocks.default_config}})

    # Load genesis config
    update_config_from_genesis_json(config, config['eth']['genesis'])

    bc = config['eth']['block']
    pprint(bc)
    env = Env(DB(), bc)

    genesis = blocks.genesis(env)
    for address, value_dict in alloc.items():
        value = value_dict.values()[0]
        assert genesis.get_balance(address) == value


@pytest.mark.parametrize('profile', PROFILES.keys())
def test_profile(profile):
    config = dict(eth=dict())

    konfig.update_config_with_defaults(config, {'eth': {'block': blocks.default_config}})

    # Set config values based on profile selection
    merge_dict(config, PROFILES[profile])

    # Load genesis config
    update_config_from_genesis_json(config, config['eth']['genesis'])

    bc = config['eth']['block']
    pprint(bc)
    env = Env(DB(), bc)

    genesis = blocks.genesis(env)
    assert genesis.hash.encode('hex') == config['eth']['genesis_hash']
