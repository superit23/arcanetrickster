from arcane.network.interface import NetworkInterface
from arcane.dhcp.server import DHCPServer
from arcane.dhcp.subleaser import DHCPSubleaser
from arcane.dhcp.releaser import DHCPReleaser
from arcane.dns.client import DNSClient
import argparse
arg_parser = argparse.ArgumentParser(
                    prog='Arcane Trickster',
                    description="""Rogue DHCP Server: DHCP Starvation, DHCP Hijacking,
                    Ma\'am-in-the Middle DHCP Subleasing(LANlady)'""",
                    epilog='Text at the bottom of help')


#eth0   = NetworkInterface("eth0")
#enp0s3  = NetworkInterface("enp0s3")
#enp0s8 = NetworkInterface("enp0s8")
#server = DHCPServer(enp0s3, DHCPSubleaser(enp0s3))
#server = DHCPServer(enp0s3, DHCPRangeLeaser(enp0s3, IPv4Address("10.10.10.10"), IPv4Address("10.10.10.239"), routes=[]))

#server   = DHCPServer(enp0s3, DHCPSubleaser(enp0s3))
#releaser = DHCPReleaser(enp0s3, server.lease_generator, '10.10.10.1')
dns_client = DNSClient()
dns_client.send_query("amazon.com", "A")

dns_client.thread.join()
#enp0s3.thread.join()

