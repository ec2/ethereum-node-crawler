import struct
import rlp
import collections

ienc = int_to_big_endian = rlp.sedes.big_endian_int.serialize


def big_endian_to_int(s):
    return rlp.sedes.big_endian_int.deserialize(s.lstrip('\x00'))

idec = big_endian_to_int


def int_to_big_endian4(integer):
    ''' 4 bytes big endian integer'''
    return struct.pack('>I', integer)

ienc4 = int_to_big_endian4


node_uri_scheme = 'enode://'


def host_port_pubkey_from_uri(uri):
    assert uri.startswith(node_uri_scheme) and '@' in uri and ':' in uri, uri
    pubkey_hex, ip_port = uri[len(node_uri_scheme):].split('@')
    assert len(pubkey_hex) == 2 * 512 / 8
    ip, port = ip_port.split(':')
    return ip, port, pubkey_hex.decode('hex')


def host_port_pubkey_to_uri(host, port, pubkey):
    assert len(pubkey) == 512 / 8
    return '%s%s@%s:%d' % (node_uri_scheme, pubkey.encode('hex'),
                           host, port)


# ###### config helpers ###############

def hex_decode_config(self):
    def _with_dict(d):
        "recursively search and decode hex encoded data"
        for k, v in d.items():
            if k.endswith('_hex'):
                d[k[:-len('_hex')]] = v.decode('hex')
            if isinstance(v, dict):
                _with_dict(v)
    _with_dict(self.config)


def update_config_with_defaults(config, default_config):
    for k, v in default_config.iteritems():
        if isinstance(v, collections.Mapping):
            r = update_config_with_defaults(config.get(k, {}), v)
            config[k] = r
        elif k not in config:
            config[k] = default_config[k]
    return config


# ###### colors ###############

COLOR_FAIL = '\033[91m'
COLOR_BOLD = '\033[1m'
COLOR_UNDERLINE = '\033[4m'
COLOR_END = '\033[0m'

colors = ['\033[9%dm' % i for i in range(0, 7)]
colors += ['\033[4%dm' % i for i in range(1, 8)]

def cstr(num, txt):
    return '%s%s%s' % (colors[num % len(colors)], txt, COLOR_END)

def cprint(num, txt):
    print cstr(num, txt)

def phx(x):
    return x.encode('hex')[:8]

if __name__ == '__main__':
    for i in range(len(colors)):
        cprint(i, 'test')
