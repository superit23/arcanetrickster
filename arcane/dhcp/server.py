from arcane.dhcp.lease_generator import DHCPLeaseGenerator
from arcane.dhcp.lease import DHCPLease
from arcane.network.interface import NetworkInterface
from arcane.events import NetworkInterfaceEvent, DHCPServerEvent
from arcane.runtime import on_event, trigger_event, api
from arcane.threaded_worker import ThreadedWorker
from arcane.exceptions import DHCPLeaseExpiredException, DHCPLeasePoolExhaustedException
from scapy.all import DHCP, IP, BOOTP



class DHCPServer(ThreadedWorker):
    def __init__(self, interface: NetworkInterface, lease_generator: DHCPLeaseGenerator, **options) -> None:
        self.lease_generator = lease_generator
        self.interface       = interface
        self.options         = options
        super().__init__()


    def __repr__(self):
        return f"<DHCPServer: interface={self.interface.name}, num_leases={self.num_leases}, num_claimed={len(self.lease_generator.claimed)}>"


    @property
    def num_leases(self):
        return len(self.lease_generator.leases)


    @on_event(NetworkInterfaceEvent.READ, lambda iface, proto, packet: DHCP in packet)
    @api
    def handle_packet(self, iface, proto, packet):
        self.handle_dhcp_discover(packet)
        self.handle_dhcp_request(packet)


    def _inject_options(self, lease):
            lease = lease.copy()
            lease.options.update(self.options)
            return lease


    def handle_dhcp_discover(self, packet):
        if ("message-type", 1) in packet[DHCP].options:
            self.log.debug(f"Handling DHCPDISCOVER for {packet.src}")

            if packet[IP].src == "0.0.0.0":
                dst_ip = "255.255.255.255"
                ip     = self.lease_generator.mac_ip_map.get(packet.src, "DNE")
            else:
                dst_ip = packet[IP].src
                ip     = dst_ip


            try:
                # Give them their current IP if we have it
                if ip in self.lease_generator.claimed and self.lease_generator.claimed[ip][2] == packet.src:
                    lease = self.lease_generator.renew(ip)
                    self.log.info(f"Renewing {lease.ip_address} for {packet.src}")
                else:
                    lease = self.lease_generator.claim(packet.src)
                    self.log.info(f"Offering {lease.ip_address} to {packet.src}")
                
                # Inject our options into it
                lease = self._inject_options(lease)

                self.interface.send(lease.build_offer_packet(xid=packet[BOOTP].xid, dst_ip=dst_ip, dst_mac=packet.src, siaddr=self.interface.ip_address, yiaddr=lease.ip_address))
                trigger_event(DHCPServerEvent.LEASE_OFFERED, packet.src, lease)

            except DHCPLeaseExpiredException:
                self.log.info(f"Denying lease for {lease_ip} to {packet.src}")
                nak = DHCPLease.build_nak_packet(xid=packet[BOOTP].xid, dst_ip=packet[IP].src, dst_mac=packet.src, src_ip=self.interface.ip_address)
                self.interface.send(nak)
                trigger_event(DHCPServerEvent.LEASE_DENIED, packet.src, lease_ip)
            

            except DHCPLeasePoolExhaustedException:
                self.log.error("No leases to offer; skipping")



    def handle_dhcp_request(self, packet):
        if ("message-type", 3) in packet[DHCP].options:
            self.log.debug(f"Handling DHCPREQUEST for {packet.src}")

            if packet[IP].src == "0.0.0.0":
                if packet[BOOTP].ciaddr == '0.0.0.0':
                    lease_ip = [opt for opt in packet[DHCP].options if opt[0] == "requested_addr"][0][1]
                else:
                    lease_ip = packet[BOOTP].ciaddr
            else:
                lease_ip = packet[IP].src


            try:
                # if lease_ip in self.lease_generator.claimed and self.lease_generator.claimed[lease_ip][2] == packet.src:
                # If the lease isn't taken and they want it, give it to them. Otherwise, if it's taken, it must match the MAC
                if (lease_ip not in self.lease_generator.claimed) or lease_ip in self.lease_generator.claimed and self.lease_generator.claimed[lease_ip][2] == packet.src:
                    lease = self.lease_generator.renew(lease_ip)
                    lease = self._inject_options(lease)
                    self.log.info(f"Sending lease for {lease.ip_address} to {packet.src}")

                    ack = lease.build_ack_packet(xid=packet[BOOTP].xid, dst_ip=packet[IP].src, dst_mac=packet.src, siaddr=self.interface.ip_address, yiaddr=lease.ip_address, ciaddr=packet[BOOTP].ciaddr, src_ip=self.interface.ip_address)
                    self.interface.send(ack)
                else:
                    raise DHCPLeaseExpiredException

            except DHCPLeaseExpiredException:
                self.log.info(f"Denying lease for {lease_ip} to {packet.src}")
                nak = DHCPLease.build_nak_packet(xid=packet[BOOTP].xid, dst_ip=packet[IP].src, dst_mac=packet.src, src_ip=self.interface.ip_address)
                self.interface.send(nak)
                trigger_event(DHCPServerEvent.LEASE_DENIED, packet.src, lease_ip)

            except DHCPLeasePoolExhaustedException:
                self.log.error("No leases to offer; skipping")