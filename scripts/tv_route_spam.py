#!/usr/bin/env python3
from tunnelvision import allowlist_events, build_dhcp_base, build_parsers
from ipaddress import IPv4Network
import time

def main():
    allowlist_events()
    args      = build_parsers()[0].parse_args()
    args_dict = dict(args._get_kwargs())
    args_dict['route'] = [f'{net}:10.13.37.1' for net in IPv4Network('0.0.0.0/1').subnets(7)]# + ['8.8.8.8/32:10.13.37.1']
    args_dict['other_options'] = [('interface-mtu', 2300)]
    interface, server, _lease_gen, _kwargs = build_dhcp_base(**args_dict)
    interface.auto_fragment = True

    # interface.thread.join()

    route_options    = server.options
    no_route_options = server.options.deepcopy()
    del no_route_options['classless_static_routes']

    while True:
        server.options = no_route_options
        time.sleep(10)
        server.options = route_options
        time.sleep(60)


if __name__ == "__main__":
    main()
