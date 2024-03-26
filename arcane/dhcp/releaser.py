from arcane.dhcp.lease_generator import DHCPLeaseGenerator
from arcane.network.interface import NetworkInterface
from arcane.events import DHCPReleaseEvent
from arcane.event_manager import trigger_event
from arcane.timer_manager import loop
from arcane.network.interface import NetworkInterface
from arcane.threaded_worker import ThreadedWorker
from arcane.dhcp.lease import DHCPLease
import time

class DHCPReleaser(ThreadedWorker):
    def __init__(self, interface: NetworkInterface, lease_generator: DHCPLeaseGenerator, server_ip: str, server_mac: str=None, sweep_time: int=30) -> None:
        self.interface       = interface
        self.lease_generator = lease_generator
        self.server_ip       = server_ip
        self.server_mac      = server_mac or self.interface.arp_table.get_or_ask(self.server_ip)
        self.sweep_time      = sweep_time
        super().__init__()


    @loop(0.25)
    def _scan(self):
        # We sleep 1 seconds per sweep to make CPU usage negigible when we own all leases
        # while also adding negigible delay between sweeps. One second was also purposefully
        # chosen to be greater than the DHCPLeaseCollector's iteration time. This gives the
        # collector time to take those IP addresses.

        # By not sleeping when encountering IPs on leases we own, we ensure that the
        # sweep time of each iteration decreases as we steal leases. This effectively
        # fixes the pacing of the packets in exchange for convergence
        sleep_time = self.sweep_time / self.interface.network.num_addresses

        for ip in self.interface.network:
            # It's not us, and we didn't assign it. Get 'em bois
            if str(ip) not in self.lease_generator.claimed and str(ip) != self.interface.ip_address:
                try:
                    time.sleep(sleep_time)
                    mac = self.interface.arp_table.get_or_ask(str(ip), sync_wait=0.1)
                    self.log.info(f"Releasing {ip} for {mac}")

                    lease = DHCPLease(
                        mac_address=mac,
                        ip_address=str(ip),
                        server_mac=self.server_mac,
                        server_ip=self.server_ip,
                        options=[],
                        duration=0
                    )
                    self.interface.send(lease.build_release_packet())
                    trigger_event(DHCPReleaseEvent.LEASE_RELEASED, lease)
                except TimeoutError:
                    self.log.debug(f"Timeout: {ip} did not respond to ARP request")
