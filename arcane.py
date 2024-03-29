from arcane.network.interface import NetworkInterface, VirtualInterface
from arcane.dhcp.server import DHCPServer
from arcane.dhcp.subleaser import DHCPSubleaser
from arcane.dhcp.range_leaser import DHCPRangeLeaser
from arcane.dhcp.releaser import DHCPReleaser
from arcane.dns.client import DNSClient
from ipaddress import IPv4Address

import logging

logging.root.setLevel(logging.DEBUG)

#eth0   = NetworkInterface("eth0")
enp0s3  = NetworkInterface("enp0s3")
#enp0s8 = NetworkInterface("enp0s8")
#server = DHCPServer(enp0s3, DHCPSubleaser(enp0s3))
server = DHCPServer(enp0s3, DHCPRangeLeaser(enp0s3, IPv4Address("10.10.10.10"), IPv4Address("10.10.10.239"), classless_static_routes=[f"8.8.8.8/32:{enp0s3.ip_address}"]))

#server   = DHCPServer(enp0s3, DHCPSubleaser(enp0s3))
#releaser = DHCPReleaser(enp0s3, server.lease_generator, '10.10.10.1')
# dns_client = DNSClient()
# dns_client.send_query("amazon.com", "A")

# dns_client.thread.join()
enp0s3.thread.join()

