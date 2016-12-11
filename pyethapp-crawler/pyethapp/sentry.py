from ethereum import utils
import random, rlp, sys
try:
    from urllib.request import build_opener
except:
    from urllib2 import build_opener


# Makes a request to a given URL (first arg) and optional params (second arg)
def make_request(*args):
    opener = build_opener()
    opener.addheaders = [('User-agent',
                          'Mozilla/5.0'+str(random.randrange(1000000)))]
    try:
        return opener.open(*args).read().strip()
    except Exception as e:
        try:
            p = e.read().strip()
        except:
            p = e
        raise Exception(p)


def warn_invalid(block, errortype='other'):
    try:
        make_request('http://badblocks.ethereum.org', {
            "block": utils.encode_hex(rlp.encode(block)),
            "errortype": errortype,
            "hints": {
                "receipts": [utils.encode_hex(rlp.encode(x)) for x in
                             block.get_receipts()],
                "vmtrace": "NOT YET IMPLEMENTED"
            }
        })
    except:
        sys.stderr.write('Failed to connect to badblocks.ethdev.com\n')
