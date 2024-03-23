from arcane.base_object import BaseObject
from arcane.exceptions import DHCPLeaseExpiredException, DHCPLeasePoolExhaustedException
import time

class DHCPLeaseGenerator(BaseObject):
    def __init__(self) -> None:
        self.claimed    = {}
        self.mac_ip_map = {}


    def renew(self, ip_address: str):
        if ip_address in self.claimed:
            old_lease, expiration, mac_address = self.claimed[ip_address]

            # Make sure that they actually have the IP
            if ip_address == self.mac_ip_map.get(mac_address, "DNE"):
                if time.time() > expiration:
                    for lease in reversed(self.leases):
                        if hash(lease) == hash(old_lease):
                            self.log.debug(f"Renewing lease {repr(lease)}")
                            old_lease.renew(lease)
                            return lease
                else:
                    return old_lease

        raise DHCPLeaseExpiredException(ip_address)


    def claim(self, mac_address: str):
        for lease in reversed(self.leases):
            # Release it first if it expired
            if lease.ip_address in self.claimed:
                old_lease, expiration, mac_address = self.claimed[lease.ip_address]

                if time.time() > expiration:
                    self.release(old_lease.ip_address)
                else:
                    continue


            if lease.is_expired:
                raise DHCPLeasePoolExhaustedException("Expired lease in renewal list")

            # Handle claims
            self.claimed[lease.ip_address] = (lease, lease.expiration, mac_address)
            self.mac_ip_map[mac_address]   = lease.ip_address
            self.log.debug(f"Claiming lease {repr(lease)}")
            return lease

        raise DHCPLeasePoolExhaustedException


    def release(self, ip_address: str=None):
        self.log.debug(f"Releasing lease {repr(ip_address)}")
        del self.claimed[ip_address]
