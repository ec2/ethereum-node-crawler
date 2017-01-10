import random
import gevent
import socket
import atexit
import time
import datetime
import threading
import csv
from gevent.server import StreamServer
from gevent.socket import create_connection, timeout
from service import WiredService
from protocol import BaseProtocol
from p2p_protocol import P2PProtocol
import kademlia
from peer import Peer
import crypto
import utils
from devp2p import discovery
import slogging
import sys

#log = slogging.get_logger('p2p.peermgr')
slogging.configure(':DEBUG')
root_logger = slogging.getLogger()
if root_logger.handlers == []:
    root_logger.addHandler(slogging.logging.StreamHandler(sys.stderr))
log = slogging.get_logger('p2p')

from collections import defaultdict

class NullApp():
    services = {}
    config = {'node':
              {'privkey_hex': 'b3b9736ba5e4b9d0f85231291316c7fd82bde4ae80bb7ca98175cf6d11c0c4eb'},
              'result_dir': './results/',
              'prev_routing_table':'./routing-table_170109-104758.csv',
              'client_version_string':'totallyordinarynode',
              'prev_peers':""}
              



class PeerManager(WiredService):

    """
    todo:
        connects new peers if there are too few
        selects peers based on a DHT
        keeps track of peer reputation
        saves/loads peers (rather discovery buckets) to disc

    connection strategy
        for service which requires peers
            while num peers > min_num_peers:
                    gen random id
                    resolve closest node address
                    [ideally know their services]
                    connect closest node
    """
    name = 'peermanager'
    required_services = []
    wire_protocol = P2PProtocol
    default_config = dict(p2p=dict(bootstrap_nodes=[],
                                   min_peers=10000,
                                   max_peers=10000,
                                   listen_port=0,
                                   listen_host='0.0.0.0'),
                          log_disconnects=False,
                          node=dict(privkey_hex=''))

    connect_timeout = 2.
    connect_loop_delay = 0.1
    discovery_delay = 0.5
    routing_refresh_timer = 600
    t = None
    init_load = True
    result_dir = "./results"
    prev_routing_table = "routing-table_170108-145306.csv"
    prev_peers = "peers_170108-021550.csv"
    json_file = None
    pubkey_list = []
    pubkey_refresh_timer = 14400

    peers_tried = {}

    def __init__(self, app):
        log.info('PeerManager init')
        WiredService.__init__(self, app)
        self.peers = []
        self.errors = PeerErrors() if self.config['log_disconnects'] else PeerErrorsBase()
        self.result_dir = self.config["result_dir"] if self.config["result_dir"] != "" else self.result_dir
        self.prev_routing_table = self.config["prev_routing_table"] if self.config["prev_routing_table"] != "" else self.prev_routing_table
        self.prev_peers = self.config["prev_peers"] if self.config["prev_peers"] != "" else self.prev_peers

        # setup nodeid based on privkey
        if 'id' not in self.config['p2p']:
            self.config['node']['id'] = crypto.privtopub(
                self.config['node']['privkey_hex'].decode('hex'))

        self.listen_addr = (self.config['p2p']['listen_host'], self.config['p2p']['listen_port'])

    def on_hello_received(self, proto, version, client_version_string, capabilities,
                          listen_port, remote_pubkey):
        log.debug('hello_received', peer=proto.peer, num_peers=len(self.peers))
#        if len(self.peers) > self.config['p2p']['max_peers']:
#            log.debug('too many peers', max=self.config['p2p']['max_peers'])
#            proto.send_disconnect(proto.disconnect.reason.too_many_peers)
        #            return False

        print 'ip_port', proto.peer.ip_port
        address = proto.peer.ip_port
        self.peers_tried[address] = client_version_string
        
        #proto.peer.stop()


        if remote_pubkey in [p.remote_pubkey for p in self.peers if p != proto.peer]:
            log.debug('connected to that node already')
            proto.send_disconnect(proto.disconnect.reason.useless_peer)
            return False

        return True

    @property
    def wired_services(self):
        return [s for s in self.app.services.values() if isinstance(s, WiredService)]

    def broadcast(self, protocol, command_name, args=[], kargs={},
                  num_peers=None, exclude_peers=[]):
        log.debug('broadcasting', protcol=protocol, command=command_name,
                  num_peers=num_peers, exclude_peers=exclude_peers)
        assert num_peers is None or num_peers > 0
        peers_with_proto = [p for p in self.peers
                            if protocol in p.protocols and p not in exclude_peers]

        if not peers_with_proto:
            log.debug('no peers with proto found', protos=[p.protocols for p in self.peers])
        num_peers = num_peers or len(peers_with_proto)
        for peer in random.sample(peers_with_proto, min(num_peers, len(peers_with_proto))):
            log.debug('broadcasting to', proto=peer.protocols[protocol])
            func = getattr(peer.protocols[protocol], 'send_' + command_name)
            func(*args, **kargs)
            # sequential uploads
            # wait until the message is out, before initiating next
            peer.safe_to_read.wait()
            log.debug('broadcasting done', ts=time.time())

    def _start_peer(self, connection, address, remote_pubkey=None):
        # create peer

        self.peers_tried[address] = None
        
        peer = Peer(self, connection, remote_pubkey=remote_pubkey)
        log.debug('created new peer', peer=peer, fno=connection.fileno())
        self.peers.append(peer)

        # loop
        peer.start()
        log.debug('peer started', peer=peer, fno=connection.fileno())
        assert not connection.closed
        return peer

    def connect(self, address, remote_pubkey):
        log.debug('connecting', address=address)
        log.info('connecting', address=address)
        """
        gevent.socket.create_connection(address, timeout=Timeout, source_address=None)
        Connect to address (a 2-tuple (host, port)) and return the socket object.
        Passing the optional timeout parameter will set the timeout
        getdefaulttimeout() is default
        """
        try:
            connection = create_connection(address, timeout=self.connect_timeout)
        except socket.timeout:
            log.debug('connection timeout', address=address, timeout=self.connect_timeout)
            self.errors.add(address, 'connection timeout')
            return False
        except socket.error as e:
            log.debug('connection error', errno=e.errno, reason=e.strerror)
            self.errors.add(address, 'connection error')
            return False
        log.debug('connecting to', connection=connection)
        p = self._start_peer(connection, address, remote_pubkey)
        p.join()
        return True

    def _bootstrap(self, bootstrap_nodes=[]):
        for uri in bootstrap_nodes:
            ip, port, pubkey = utils.host_port_pubkey_from_uri(uri)
            log.info('connecting bootstrap server', uri=uri)
            try:
                self.connect((ip, port), pubkey)
            except socket.error:
                log.warn('connecting bootstrap server failed')

    def start(self):
        log.info('starting peermanager')
        #super(PeerManager, self).start()  # Does nothing, unless we define _run

        self.load_routing_table()
        #self.save_data()

    def num_peers(self):
        ps = [p for p in self.peers if p]
        aps = [p for p in ps if not p.is_stopped]
        if len(ps) != len(aps):
            log.error('stopped peers in peers list', inlist=len(ps), active=len(aps))
        return len(aps)

    def load_routing_table(self):
        nodes = []
        try:
            #routing = self.app.services.discovery.protocol.kademlia.routing
            current_time = "{:%y%m%d-%H%M%S}".format(datetime.datetime.now())
            filename = "{}/{}".format(self.result_dir, self.prev_routing_table)
            log.info('loading previous routing table', file=filename, timestamp=current_time)
            greenlets = []            

            # HARDCODED winterfell node
            if 1:
                pubkey = "5fbca9b7b103c1e5cb1bab548980bf9de7ac559fc0ad61a0fa7fe96350e6cddf75bdd85e9070d3f45a97781532b99fc4bba4a3c4873329f1dce7d1a3f8c3ce0b".decode('hex')
                ip = '72.36.89.11'
                tcp_port = 30303
                greenlets.append(gevent.spawn(self.connect, (ip, tcp_port), pubkey))

            if 1:
              with open(filename, "r") as file_obj:
                csvfile = csv.reader(file_obj, delimiter=',')
                for row in list(csvfile)[:10]:
                    if len(row) != 6:
                        continue
                    pubkey = row[0].decode('hex')
                    ip = row[1]
                    tcp_port = int(row[2])
                    udp_port = int(row[3])
                    reputation = row[4]
                    rlpx_version = row[5]

                    address = discovery.Address(ip, udp_port, tcp_port=tcp_port)
                    node = discovery.Node(pubkey, address=address)
                    node.reputation = reputation
                    node.rlpx_version = rlpx_version
                    #routing.add_node(node)
                    nodes.append(node)
                    log.info('add_node: ' + str(node))
                    greenlets.append(gevent.spawn(self.connect, (ip, tcp_port), pubkey))
            gevent.joinall(greenlets)
            gevent.sleep(self.connect_loop_delay)
            log.info('previous routing table loaded', num_nodes=len(nodes))

        except AttributeError:
            # TODO: Is this the correct thing to do here?
            log.error("Discovery service not available. Failed to load routing table.")

    def save_routing_table(self):
        nodes = None
        try:
            kademlia_proto = self.app.services.discovery.protocol.kademlia
            nodes = set(kademlia_proto.routing)
            current_time = "{:%y%m%d-%H%M%S}".format(datetime.datetime.now())
            filename = "{}/routing-table_{}.csv".format(self.result_dir, current_time)
            log.info('saving routing table', file=filename, timestamp=current_time)
            file_obj = open(filename, "w")
            greenlets = []
            for node in nodes:
                file_obj.write("{},{},{},{},{},{}\n".format(node.pubkey.encode('hex'), node.address.ip, node.address.tcp_port, node.address.udp_port, node.reputation, node.rlpx_version))
                if node.pubkey in [p.remote_pubkey for p in self.peers]:
                    continue
#                self.connect((node.address.ip, node.address.tcp_port), node.pubkey)
#                gevent.sleep(self.connect_loop_delay)
                greenlets.append(gevent.spawn(self.connect, (node.address.ip, node.address.tcp_port), node.pubkey))
            gevent.joinall(greenlets)
            gevent.sleep(self.connect_loop_delay)
            file_obj.close()

        except AttributeError:
            # TODO: Is this the correct thing to do here?
            log.error("Discovery service not available. Failed to save routing table.")
        return nodes

    def save_peers(self):
        current_time = "{:%y%m%d-%H%M%S}".format(datetime.datetime.now())
        filename = "{}/peers_{}.csv".format(self.result_dir, current_time)
        log.info('saving peers', file=filename, timestamp=current_time)
        file_obj = open(filename, "w")
        for p in self.peers:
            try:
                ip, tcp_port = p.ip_port
                p2p_proto = p.protocols.values()[0]
                p2p_proto_monitor = p2p_proto.monitor
                file_obj.write("{},{},{},{},{},{},{},{}\n".format(p.remote_pubkey.encode('hex'), ip, tcp_port, p.remote_client_version, p2p_proto_monitor.last_request, p2p_proto_monitor.last_response, p2p_proto_monitor.latency(), p2p_proto.version))
            except:
                continue 
        file_obj.close()

    def save_data(self):
        if self.init_load:
            self.init_load = False
        else:
            nodes = self.save_routing_table()
            self.save_peers()
        self.t = threading.Timer(self.routing_refresh_timer, self.save_data)
        self.t.start()

    def clear_pubkey_list(self):
        if self.json_file:
            self.json_file.close()
        self.pubkey_list = []
        current_time = "{:%y%m%d-%H%M%S}".format(datetime.datetime.now())
        filename = "{}/hello-peers_{}.json".format(self.result_dir, current_time)
        self.json_file = open(filename, "w")
        self.pubkey_t = threading.Timer(self.pubkey_refresh_timer, self.clear_pubkey_list)
        self.pubkey_t.start()

    def stop(self):
        log.info('stopping peermanager')
        self.t.cancel()
        self.pubkey_t.cancel()
        for peer in self.peers:
            peer.stop()
        super(PeerManager, self).stop()


class PeerErrorsBase(object):
    def add(self, address, error, client_version=''):
        pass


class PeerErrors(PeerErrorsBase):
    def __init__(self):
        self.errors = dict()  # node: ['error',]
        self.client_versions = dict()  # address: client_version

        def report():
            for k, v in self.errors.items():
                print k, self.client_versions.get(k, '')
                for e in v:
                    print '\t', e

        atexit.register(report)

    def add(self, address, error, client_version=''):
        self.errors.setdefault(address, []).append(error)
        if client_version:
            self.client_versions[address] = client_version
