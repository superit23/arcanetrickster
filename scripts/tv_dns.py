#!/usr/bin/env python3
from arcane.network.interface import NetworkInterface
from arcane.dns.server import DNSServer
from arcane.dns.intercept_resolver import DNSInterceptResolver
from arcane.core.runtime import RUNTIME, api, on_event
from arcane.core.events import NetworkInterfaceEvent, DNSServerEvent, DNSResolverEvent, DNSClientEvent, SocketEvent
from arcane.dhcp.server import DHCPServer
from arcane.dhcp.range_leaser import DHCPRangeLeaser
from enum import Enum
import argparse
from ipaddress import IPv4Address
import logging
import argparse
import time


parser = argparse.ArgumentParser(prog='TunnelVision DNS', description='DNS Server will intercept queries then determine to proxy or answer with a local record.')
parser.add_argument('-i', '--interface', help="Interface to listen on", required=True)
parser.add_argument('-p', '--port', default=53, type=int, help="The port to run the DNS Server on")
parser.add_argument('-v', '--verbose', action="store_true", help="Print DEBUG messages to console")

def main():
    args = parser.parse_args()
    logging.root.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    RUNTIME.event_manager.log_filter.allowlist_events.add(DNSServerEvent.QUERY_RECEIVED)
    RUNTIME.event_manager.log_filter.allowlist_events.add(DNSResolverEvent.ANSWER_RECEIVED)
    RUNTIME.event_manager.log_filter.allowlist_events.add(DNSResolverEvent.TIMEOUT_RECEIVED)
    RUNTIME.event_manager.log_filter.allowlist_events.add(DNSClientEvent.ANSWER_RECEIVED)
    RUNTIME.event_manager.log_filter.allowlist_events.add(DNSClientEvent.TIMEOUT_RECEIVED)
    RUNTIME.event_manager.log_filter.allowlist_events.add(SocketEvent.READ)
    
    interface    = NetworkInterface(args.interface)
    dns_resolver = DNSInterceptResolver()
    dns_server   = DNSServer(interface, dns_resolver)

    lease_gen = DHCPRangeLeaser(interface, IPv4Address("10.13.37.8"), IPv4Address("10.13.37.63"))
    server    = DHCPServer(interface, lease_gen, lease_time=20, router="10.13.37.1", name_server="10.13.37.1")

    dns_server.thread.join()


if __name__ == "__main__":
    main()


