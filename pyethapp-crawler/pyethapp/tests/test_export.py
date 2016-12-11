from StringIO import StringIO
import subprocess
from pyethapp.app import app
from click.testing import CliRunner
from ethereum.blocks import BlockHeader
import rlp
import pytest


@pytest.mark.xfail  # can not work without mock-up chain
def test_export():
    # requires a chain with at least 5 blocks
    assert subprocess.call('pyethapp export', shell=True) != 0
    assert subprocess.call('pyethapp export --from -1 -', shell=True) != 0
    assert subprocess.call('pyethapp export --to -3 -', shell=True) != 0
    assert subprocess.call('pyethapp export --from 4 --to 2 -', shell=True) != 0

    result = subprocess.Popen('pyethapp export --from 2 --to 4 -', shell=True,
                              stdout=subprocess.PIPE)
    result.wait()
    assert result.returncode == 0
    s = result.stdout.read()

    headers = []
    end = 0
    while end < len(s):
        item, end = rlp.codec.consume_item(s, end)
        headers.append(BlockHeader.deserialize(item[0]))
    assert [header.number for header in headers] == [2, 3, 4]
