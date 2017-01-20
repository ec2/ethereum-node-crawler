import random
import gevent
import socket
import atexit
import time
import csv
from gevent.server import StreamServer
from gevent.socket import create_connection, timeout
from devp2p import multiplexer
from devp2p import rlpxcipher
from devp2p.service import WiredService
from devp2p.protocol import BaseProtocol
from devp2p.p2p_protocol import P2PProtocol
from devp2p import kademlia
from devp2p.peer import *
from devp2p.peermanager import *
from devp2p import crypto
from devp2p.crypto import ECIESDecryptionError
from devp2p import utils

from devp2p import slogging
log = slogging.get_logger('p2p.peermgr')

class NewPeer(Peer):
    @property
    def capabilities(self):
        return [('eth', 61), ('eth', 62), ('eth', 63), ('p2p', 4)]

    def _handle_packet(self, packet):
        assert isinstance(packet, multiplexer.Packet)
        try:
            protocol, cmd_id = self.protocol_cmd_id_from_packet(packet)
            cmd = protocol.cmd_by_id[cmd_id]
        except (UnknownCommandError, KeyError) as e:
            log.error('received unknown cmd', error=e, packet=packet)
            return
        log.debug('recv packet ', cmd=cmd, protocol=protocol.name, orig_cmd_id=packet.cmd_id)
        packet.cmd_id = cmd_id  # rewrite
        protocol.receive_packet(packet)

    def _run_ingress_message(self):
        log.debug('wtfwtfpeer starting main loop')
        assert not self.connection.closed, "connection is closed"
        gevent.spawn(self._run_decoded_packets)
        gevent.spawn(self._run_egress_message)

        while not self.is_stopped:
            self.safe_to_read.wait()
            try:
                gevent.socket.wait_read(self.connection.fileno())
            except gevent.socket.error as e:
                log.debug('read error', errno=e.errno, reason=e.strerror, peer=self)
                self.report_error('network error %s' % e.strerror)
                if e.errno in(9,):
                    # ('Bad file descriptor')
                    self.stop()
                else:
                    raise e
                    break
            try:
                imsg = self.connection.recv(4096)
            except gevent.socket.error as e:
                log.debug('read error', errno=e.errno, reason=e.strerror, peer=self)
                self.report_error('network error %s' % e.strerror)
                if e.errno in(50, 54, 60, 65, 104):
                    # (Network down, Connection reset by peer, timeout, no route to host,
                    # Connection reset by peer)
                    self.stop()
                else:
                    raise e
                    break
            if imsg and (len(imsg) >= 210):
                log.debug('read data', ts=time.time(), size=len(imsg))
                try:
                    self.mux.add_message(imsg)
                except (rlpxcipher.RLPxSessionError, ECIESDecryptionError) as e:
                    log.debug('rlpx session error', peer=self, error=e)
                    self.report_error('rlpx session error')
                    self.stop()
                except multiplexer.MultiplexerError as e:
                    log.debug('multiplexer error', peer=self, error=e)
                    self.report_error('multiplexer error')
                    self.stop()

    _run = _run_ingress_message


class PeerCrawler(PeerManager):
    name = 'peercrawler'
    required_services = []
    wire_protocol = P2PProtocol
    default_config = dict(p2p=dict(listen_port=30303,listen_host='0.0.0.0'),
                          log_disconnects=False)

    connect_timeout = 2.
    connect_loop_delay = 0.1
    discovery_delay = 0.5

    def __init__(self, app):
        log.info('PeerCrawler init')
        WiredService.__init__(self, app)
        self.peers = []
        self.errors = PeerErrors() if self.config['log_disconnects'] else PeerErrorsBase()

    def on_hello_received(self, proto, version, client_version_string, capabilities,
                          listen_port, remote_pubkey):
        log.debug('hello_received', peer=proto.peer, num_peers=len(self.peers))
        if remote_pubkey in [p.remote_pubkey for p in self.peers if p != proto.peer]:
            log.debug('connected to that node already')
            proto.send_disconnect(proto.disconnect.reason.useless_peer)
            return False

        return True

    def _start_peer(self, connection, address, remote_pubkey=None):
        # create peer
        peer = NewPeer(self, connection, remote_pubkey=remote_pubkey)
        log.debug('created new peer', peer=peer, fno=connection.fileno())
        self.peers.append(peer)

        # loop
        peer.start()
        log.debug('peer started', peer=peer, fno=connection.fileno())
        assert not connection.closed
        return peer

    def start(self):
        log.info('starting peercrawler')
        gevent.spawn(self._crawl_loop)

    def _crawl_loop(self):
        nodes = []
        filename = self.config['prev_routing_table']
        log.info('loading known nodes from ', filename=filename)
        file_obj = open(filename, 'r')
        greenlets = []
        csvfile = csv.reader(file_obj, delimiter=',')
        for row in csvfile:
            if len(row) != 6:
                continue
            pubkey = row[0].decode('hex')
            nodes.append((pubkey, row[1], int(row[2])))
        csvfile = None
        file_obj.close()

#        while not self.is_stopped:
        for pubkey, ip, tcp_port in nodes:
            greenlets.append(gevent.spawn(self.connect, (ip, tcp_port), pubkey))
        gevent.joinall(greenlets)
        gevent.sleep(self.connect_loop_delay)
        for i in range(3):
            log.info('============== ', peers=self.num_peers())
            log.info('peer list', peers=len(self.peers))
            time.sleep(5)
        evt = gevent.event.Event()
        evt.wait()

    def stop(self):
        log.info('stopping peercrawler')
        for peer in self.peers:
            peer.stop()
        super(PeerManager, self).stop()
