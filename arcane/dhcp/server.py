from arcane.dhcp.lease_generator import DHCPLeaseGenerator
from arcane.network.network_interface import NetworkInterface
from arcane.events import NetworkInterfaceEvent
from arcane.event_manager import on_event
from arcane.network.network_interface import NetworkInterface
from arcane.threaded_worker import ThreadedWorker, api
from arcane.exceptions import DHCPLeaseExpiredException
from scapy.all import DHCP, IP, BOOTP
import time


class DHCPServer(ThreadedWorker):
    def __init__(self, interface: NetworkInterface, lease_generator: DHCPLeaseGenerator) -> None:
        self.lease_generator = lease_generator
        self.interface       = interface


    def __repr__(self):
        return f"<DHCPServer: interface={self.interface.name}, num_leases={self.num_leases}, num_claimed={len(self.lease_generator.claimed)}>"


    @property
    def num_leases(self):
        return len(self.lease_generator.leases)


    @on_event(NetworkInterfaceEvent.READ)
    @api
    def handle_packet(self, iface, packet):
        if DHCP in packet:
            if not ("message-type", 2) in packet[DHCP].options and not ("message-type", 5) in packet[DHCP].options:
                print(packet[DHCP].options)
            self.handle_dhcp_discover(packet)
            self.handle_dhcp_request(packet)


    def handle_dhcp_discover(self, packet):
        if ("message-type", 1) in packet[DHCP].options:
            self.log.info(f"Handling DHCPDISCOVER for {packet.src}")

            packet.show()

            if packet[IP].src == "0.0.0.0":
                dst_ip = "255.255.255.255"
                ip     = self.lease_generator.mac_ip_map.get(packet.src, "DNE")
            else:
                dst_ip = packet[IP].src
                ip     = dst_ip


            # Give them their current IP if we have it
            if ip in self.lease_generator.claimed:
                lease = self.lease_generator.renew(ip)
            else:
                lease = self.lease_generator.claim(packet.src)


            self.log.info(f"Offering {lease.ip_address} to {packet.src}")

            self.interface.send(lease.build_offer_packet(xid=packet[BOOTP].xid, dst_ip=dst_ip, dst_mac=packet.src, siaddr=self.interface.ip_address, yiaddr=lease.ip_address))


    def handle_dhcp_request(self, packet):
        if ("message-type", 3) in packet[DHCP].options:
            self.log.info(f"Handling DHCPREQUEST for {packet.src}")

            packet.show()

            if packet[IP].src == "0.0.0.0":
                if packet[BOOTP].ciaddr == '0.0.0.0':
                    lease_ip = [opt for opt in packet[DHCP].options if opt[0] == "requested_addr"][0][1]
                else:
                    lease_ip = packet[BOOTP].ciaddr
            else:
                lease_ip = packet[IP].src

            try:
                lease = self.lease_generator.renew(lease_ip)
                self.log.info(f"Sending lease for {lease.ip_address} to {packet.src}")

                ack = lease.build_ack_packet(xid=packet[BOOTP].xid, dst_ip=packet[IP].src, dst_mac=packet.src, siaddr=self.interface.ip_address, yiaddr=lease.ip_address, ciaddr=packet[BOOTP].ciaddr, src_ip=self.interface.ip_address)
                ack.show()
                self.interface.send(ack)

            except DHCPLeaseExpiredException:
                self.log.info(f"Sending DHCPNAK to {packet.src}")
                nak = self.lease_generator.leases[0].build_nak_packet(xid=packet[BOOTP].xid, dst_ip=packet[IP].src, dst_mac=packet.src, src_ip=self.interface.ip_address)
                nak.show()
                self.interface.send(nak)
