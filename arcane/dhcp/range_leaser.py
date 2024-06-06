from arcane.network.interface import NetworkInterface
from arcane.dhcp.lease_generator import DHCPLeaseGenerator
from arcane.dhcp.lease import DHCPLease
from arcane.utilities import random_mac
from ipaddress import IPv4Address
import time

class DHCPRangeLeaser(DHCPLeaseGenerator):
    def __init__(self, interface: NetworkInterface, ip_address_start: IPv4Address, ip_address_stop: IPv4Address, **options) -> None:
        self.interface        = interface
        self.ip_address_start = ip_address_start
        self.ip_address_stop  = ip_address_stop
        self.options          = options
        self.options.update({
            'router': options.get('router', interface.ip_address),
            'subnet_mask': options.get('subnet_mask', interface.subnet_mask),
            'lease_time': options.get('lease_time', 60)
        })
        super().__init__()

        lease_range  = range(int.from_bytes(self.ip_address_start.packed, 'big'), int.from_bytes(self.ip_address_stop.packed, 'big')+1)
        self._leases = [DHCPLease(random_mac(), str(IPv4Address(ip_int)), interface.mac_address, interface.ip_address, self.options, self.options['lease_time']) for ip_int in lease_range]


    @property
    def leases(self):
        if (self._leases[0].expiration - (self.options['lease_time'] // 2)) < time.time():
            for lease in self._leases:
                if lease not in self.claimed:
                    lease.start_time = time.time()
        
        return self._leases

