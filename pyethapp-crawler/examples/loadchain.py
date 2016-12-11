from pyethapp.leveldb_service import LevelDB
from pyethapp.config import default_data_dir
from ethereum.chain import Chain
from ethereum.ethpow import check_pow
from ethereum.utils import big_endian_to_int, sha3
from ethereum.config import Env
import rlp
import os
import sys


def get_chain(data_dir=default_data_dir):
    """
    returns an ethereum.chain.Chain instance
    """
    dbfile = os.path.join(data_dir, 'leveldb')
    db = LevelDB(dbfile)
    return Chain(Env(db))


def _check_pow(header):
    number = big_endian_to_int(header[8])
    difficulty = big_endian_to_int(header[7])
    mixhash = header[13]
    nonce = header[14]
    mining_hash = sha3(rlp.encode(header[:13]))
    assert check_pow(number, mining_hash, mixhash, nonce, difficulty)


def read_raw_blocks(chain, check_pow=False):
    """
    reads all raw blocks from the database
    from head to genesis
    """
    blk = chain.head
    i = blk.header.number
    prevhash = blk.hash
    while prevhash in chain.db:
        blk = rlp.decode(chain.db.get(prevhash))
        prevhash = blk[0][0]
        if check_pow:
            _check_pow(blk[0])
        i -= 1
        if i % 1000 == 0:
            print i


def read_blocks(chain):
    """
    reads all blocks from the database
    from head to genesis
    """
    blocks = []
    blk = chain.head
    while blk.has_parent():
        blk = blk.get_parent()
        if blk.header.number % 1000 == 0:
            print blk.header.number
            blocks.append(blk)

if __name__ == '__main__':
    chain = get_chain()
    read_blocks(chain)
