from arcane.base_object import BaseObject
from arcane.exceptions import DHCPLeaseExpiredException, DHCPLeasePoolExhaustedException
import time

class DHCPLeaseGenerator(BaseObject):
    def __init__(self) -> None:
        self.claimed    = {}
        self.mac_ip_map = {}


    def renew(self, ip_address: str):
        if ip_address in self.claimed:
            old_lease, mac_address = self.claimed[ip_address]

            # Make sure that they actually have the IP
            if ip_address == self.mac_ip_map.get(mac_address, "DNE"):
                if time.time() > old_lease.expiration:
                    for lease in reversed(self.leases):
                        # It's possible that a new version of this lease exists
                        if lease == old_lease:
                            self.log.info(f"Renewing lease {repr(lease)}")
                            old_lease.renew(lease)
                            return lease
                else:
                    # TODO: Does this make sense for the subleaser?
                    old_lease.start_time = time.time()
                    return old_lease

        raise DHCPLeaseExpiredException(ip_address)


    def claim(self, mac_address: str):
        for lease in reversed(self.leases):
            # Release it first if it expired
            if lease.ip_address in self.claimed:
                old_lease, old_mac = self.claimed[lease.ip_address]

                if time.time() > old_lease.expiration + 5:
                    self.release(old_lease.ip_address)
                else:
                    continue


            elif lease.is_expired:
                raise DHCPLeasePoolExhaustedException("Expired lease in renewal list")

            # Handle claims
            # TODO: Handle this different when we're subleasing
            lease            = lease.copy()
            lease.start_time = time.time()
            self.claimed[lease.ip_address] = (lease, mac_address)
            self.mac_ip_map[mac_address]   = lease.ip_address
            self.log.info(f"Claiming lease {repr(lease)}")
            return lease

        raise DHCPLeasePoolExhaustedException


    def release(self, ip_address: str=None):
        self.log.info(f"Releasing lease {repr(ip_address)}")
        del self.claimed[ip_address]
