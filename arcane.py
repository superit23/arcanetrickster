from arcane.network.network_interface import NetworkInterface
from arcane.dhcp.server import DHCPServer
from arcane.dhcp.subleaser import DHCPSubleaser
import argparse
arg_parser = argparse.ArgumentParser(
                    prog='Arcane Trickster',
                    description="""Rogue DHCP Server: DHCP Starvation, DHCP Hijacking,
                    Ma\'am-in-the Middle DHCP Subleasing(LANlady)'""",
                    epilog='Text at the bottom of help')

eth0 = NetworkInterface("eth0")
# enp0s3 = NetworkInterface("enp0s3")
# enp0s8 = NetworkInterface("enp0s8")
#server = DHCPServer(enp0s3, DHCPSubleaser(enp0s3))
#server = DHCPServer(enp0s3, DHCPRangeLeaser(enp0s3, IPv4Address("10.10.10.10"), IPv4Address("10.10.10.239"), routes=[]))
server = DHCPServer(eth0, DHCPSubleaser(eth0))
#releaser = DHCPReleaser(enp0s3, server.lease_generator, '10.10.10.1')

eth0.thread.join()
# router = Router([enp0s3, enp0s8])
# router.routes.add("192.168.1.0/24", None, enp0s8)
# router.routes.add("10.10.10.0/24", None, enp0s3)


# TODO Add functionality to intercept a DHCPOFFER and inject our own routes.
# TODO Add functionlity to check if a DHCPREQUEST is unicast
# TODO Add NetworkAddressTranslation functionality, we hoard leases then hand them out

# TODO DHCPServer Class
# TODO DHCPLeaseGenerator Class
# TODO Router Class (NAT)
    # The Real Router
    # Subscriber to listen for relevant packets to the virtual Router
# TODO ARP Spoof

# TODO (not priority) Storage
            # Export PCAP
