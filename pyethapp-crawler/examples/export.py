#!/usr/bin/env python
from pyethapp.leveldb_service import LevelDB
from pyethapp.config import default_data_dir
from ethereum.chain import Chain
from ethereum.config import Env
from ethereum.transactions import Transaction
import rlp
from rlp.codec import consume_length_prefix
import os
import sys


def get_chain(data_dir=default_data_dir):
    """
    returns an ethereum.chain.Chain instance
    """
    dbfile = os.path.join(data_dir, 'leveldb')
    db = LevelDB(dbfile)
    return Chain(Env(db))


def _progress(i):
    if i % 1000:
        sys.stderr.write('.')
    else:
        sys.stderr.write(str(i))
    sys.stderr.flush()


def export_blocks(chain, head_number=None):
    """
    Export blocks
    rlp and hex encoded, separated by newline
    """
    head_number = head_number or chain.head.header.number
    block_number = 0
    while block_number < head_number:
        h = chain.index.get_block_by_number(block_number)
        raw = chain.blockchain.get(h)
        print raw.encode('hex')
        _progress(block_number)
        block_number += 1


def export_transactions(chain, head_number=None):
    """
    Export transactions
    rlp and hex encoded, separated by newline
    """
    head_number = head_number or chain.head.header.number
    block_number = 0
    seen = 0
    while block_number < head_number:
        h = chain.index.get_block_by_number(block_number)
        raw = chain.blockchain.get(h)
        # block [[], [], []]
        typ, length, end = consume_length_prefix(raw, 0)
        assert typ == list
        typ, length, end = consume_length_prefix(raw, end)  # header list
        assert typ == list
        txs_start = end + length
        typ, length, end = consume_length_prefix(raw, txs_start)  # tx list
        txrlp = raw[txs_start:end + length]
        r = rlp.decode(txrlp)
        assert isinstance(r, list)
        for tx in r:
            s = rlp.encode(tx)
            rlp.decode(s, Transaction)
            print s.encode('hex')
            seen += 1
            _progress(seen)
        block_number += 1


if __name__ == '__main__':
    def usage():
        print("Usage:\n\t{} (blocks|transactions) [head_number]".format(sys.argv[0]))
        sys.exit(0)

    if len(sys.argv) == 1 or "-h" in sys.argv:
        usage()

    head_number = None
    cmd = sys.argv[1]

    if len(sys.argv) > 2:
        head_number = int(sys.argv[2])

    chain = get_chain()
    if cmd == "blocks":
        export_blocks(chain, head_number=head_number)
    elif cmd == "transactions":
        export_transactions(chain, head_number=head_number)
    else:
        usage()
