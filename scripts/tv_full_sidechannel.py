#!/usr/bin/env python3
from arcane.vpn.sidechanneler import Sidechanneler
from tunnelvision import allowlist_events, build_dhcp_base, build_parsers


def main():
    allowlist_events()
    interface, server, _lease_gen, _kwargs = build_dhcp_base(build_parsers()[0])

    input("Press enter to start SIDE CHANNEL")
    side_channeler = Sidechanneler(server, "0.0.0.0/0")
    interface.thread.join()


if __name__ == "__main__":
    main()
