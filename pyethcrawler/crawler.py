import random
import socket
import atexit
import time
import datetime
import threading
import csv
import sys
import signal
from UserDict import IterableUserDict
from collections import defaultdict
import gevent
from gevent.server import StreamServer
from gevent.socket import create_connection, timeout
from devp2p import __version__
from devp2p import crypto
from devp2p import kademlia
from devp2p import slogging
from devp2p import utils
from devp2p.app import BaseApp
from devp2p.discovery import NodeDiscovery
from devp2p.peer import Peer
from devp2p.protocol import BaseProtocol
from devp2p.p2p_protocol import P2PProtocol
from devp2p.service import BaseService
from peermanager2 import PeerManager
from testcrawler import ChainService

log = slogging.get_logger('app')
slogging.configure(config_string=':debug')

root_logger = slogging.getLogger()
if root_logger.handlers == []:
    root_logger.addHandler(slogging.logging.StreamHandler(sys.stderr))
#log = slogging.get_logger('p2p')

class BaseApp(object):
    client_name = 'pyethapp-test'
    client_version = '%s/%s/%s' % (__version__, sys.platform,
                                   'py%d.%d.%d' % sys.version_info[:3])
    client_version_string = '%s/v%s' % (client_name, client_version)
    start_console = False
    default_config = dict(BaseApp.default_config)
    default_config['client_version_string'] = client_version_string
    default_config['result_dir'] = ''
    default_config['prev_routing_table'] = ''
    default_config['prev_peers'] = ''
    default_config['p2p'] = dict(bootstrap_nodes=[],listen_port=30303,listen_host='0.0.0.0')
    privkey_hex = 'b3b9736ba5e4b9d0f85231291316c7fd82bde4ae80bb7ca98175cf6d11c0c4eb'
    pubkey = crypto.privtopub(privkey_hex.decode('hex'))
    default_config['node'] = dict(privkey_hex=privkey_hex, id=crypto.sha3(pubkey))

    def __init__(self, config=default_config):
        self.config = utils.update_config_with_defaults(config, self.default_config)
        self.services = IterableUserDict()

    def register_service(self, service):
        """
        registeres protocol with app, which will be accessible as
        app.services.<protocol.name> (e.g. app.services.p2p or app.services.eth)
        """
        assert isinstance(service, BaseService)
        assert service.name not in self.services
        log.info('registering service', service=service.name)
        self.services[service.name] = service
        setattr(self.services, service.name, service)

    def deregister_service(self, service):
        assert isinstance(service, BaseService)
        self.services.remove(service)
        delattr(self.services, service.name)

    def start(self):
        for service in self.services.values():
            service.start()

    def stop(self):
        for service in self.services.values():
            service.stop()

    def join(self):
        for service in self.services.values():
            service.join()


def main():
    # stop on every unhandled exception!
    gevent.get_hub().SYSTEM_ERROR = BaseException  # (KeyboardInterrupt, SystemExit, SystemError)

    # create app
    app = BaseApp()
    print(app.config)

    # register services
    # NodeDiscovery.register_with_app(app)
    PeerManager.register_with_app(app)
    print(app.services)

    # start app
    app.start()

    app.services['eth'] = ChainService()
    # wait for interupt
    evt = gevent.event.Event()
    # gevent.signal(signal.SIGQUIT, gevent.kill) ## killall pattern
    gevent.signal(signal.SIGQUIT, evt.set)
    gevent.signal(signal.SIGTERM, evt.set)
    gevent.signal(signal.SIGINT, evt.set)
    evt.wait()

    # finally stop
    app.stop()

if __name__ == '__main__':
    #  python app.py 2>&1 | less +F
    main()

