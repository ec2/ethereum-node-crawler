import pytest
from gevent.event import Event

from devp2p.app import BaseApp
from devp2p.service import BaseService
from ethereum import slogging
from ethereum.blocks import Block, BlockHeader
from ethereum.config import Env
from ethereum.db import DB

from pyethapp.pow_service import PoWService

DIFFICULTY = 1024  # Mining difficulty.
TIMEOUT = 15       # Timeout for single block being minded.


class ChainServiceMock(BaseService):
    name = 'chain'

    class ChainMock:
        def __init__(self):
            env = Env(DB())
            header = BlockHeader(difficulty=DIFFICULTY)
            self.head_candidate = Block(header, env=env)

    def __init__(self, app):
        super(ChainServiceMock, self).__init__(app)
        self.on_new_head_candidate_cbs = []
        self.is_syncing = False
        self.chain = self.ChainMock()
        self.mined_block = None
        self.block_mined_event = Event()

    def add_mined_block(self, block):
        assert self.mined_block is None
        self.mined_block = block
        self.block_mined_event.set()


@pytest.fixture
def app(request):
    app = BaseApp()
    ChainServiceMock.register_with_app(app)
    PoWService.register_with_app(app)
    app.start()
    request.addfinalizer(lambda: app.stop())
    return app


def test_pow_default(app):
    chain = app.services.chain
    pow = app.services.pow

    assert pow
    assert chain
    assert len(chain.on_new_head_candidate_cbs) == 1
    assert not pow.active
    assert not app.config['pow']['activated']
    assert app.config['pow']['cpu_pct'] == 100
    assert not app.config['pow']['coinbase_hex']
    assert app.config['pow']['mine_empty_blocks']


def test_pow_config(app):
    app.config['pow']['activated'] = True
    assert app.services.pow.active


def test_pow_mine_empty_block(app):
    slogging.configure("pow:trace")
    app.config['pow']['activated'] = True
    chain = app.services.chain
    e = chain.block_mined_event
    e.wait(timeout=TIMEOUT)
    assert e.is_set(), "Block has not been mined for {} s".format(TIMEOUT)
    assert chain.mined_block


def test_pow_dont_mine_empty_block(app):
    slogging.configure("pow:trace")
    app.config['pow']['mine_empty_blocks'] = False
    app.config['pow']['activated'] = True
    chain = app.services.chain
    pow = app.services.pow
    e = chain.block_mined_event
    e.wait(timeout=2)
    assert not e.is_set(), "Block has been mined"
    assert chain.mined_block is None
    assert pow.hashrate == 0, "Miner is working"
