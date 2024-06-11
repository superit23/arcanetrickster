from arcane.core.threaded_worker import ThreadedWorker, api
from arcane.network.interface import NetworkInterface
from arcane.core.events import DHCPLeaseCollectorEvent, DHCPLeaseRenewerEvent
from arcane.dhcp.lease import DHCPLease
from arcane.core.utilities import binary_search_list
from arcane.core.runtime import loop, trigger_event, on_event
from queue import Queue, Empty
import time
import random

class DHCPLeaseRenewer(ThreadedWorker):
    def __init__(self, interface: NetworkInterface) -> None:
        self.interface = interface
        self.leases    = []
        self.pending   = {}
        self.queue     = Queue()
        super().__init__()


    @on_event(DHCPLeaseCollectorEvent.NEW_LEASE)
    @api
    def lease_callback(self, lease: DHCPLease):
        self.queue.put(lease)


    def handle_new_leases(self):
        while self.queue.not_empty:
            # This literally happened. Don't delete
            try:
                lease = self.queue.get_nowait()
            except Empty:
                break

            # Handle lease renewal
            if lease in self.pending:
                self.pending[lease].renew(lease)
                del self.pending[lease]
                self.log.debug(f"Lease for ({lease.ip_address}, {lease.mac_address}) successfully renewed")
            else:
                self.log.debug(f"Appending new lease for ({lease.ip_address}, {lease.mac_address})")
                self.leases.append(lease)

            self.leases.sort(key=lambda lease: lease.expiration)


    def renew_leases(self):
        # Renew leases about to be expired
        renewal_boundary = binary_search_list(self.leases, time.time() + 30, key=lambda lease: lease.expiration, fuzzy=True)
        expired_leases   = []

        for lease in self.leases[:renewal_boundary]:
            xid = random.randint(0, 2**32-1)
            if lease.is_expired:
                expired_leases.append(lease)
                if lease in self.pending:
                    del self.pending[lease]

                trigger_event(DHCPLeaseRenewerEvent.NEW_XID, xid, lease.mac_address)
                self.interface.send(lease.build_discover_packet(xid))
            else:
                # Don't try to renew if it's already pending
                if lease not in self.pending:
                    self.log.debug(f"Renewing lease {repr(lease)}")

                    self.pending[lease] = lease
                    trigger_event(DHCPLeaseRenewerEvent.NEW_XID, xid, lease.mac_address)
                    self.interface.send(lease.build_renewal_packet(xid))

        # Prune expired leases
        for lease in expired_leases:
            idx = binary_search_list(self.leases, lease.expiration, key=lambda lease: lease.expiration)
            del self.leases[idx]

            self.log.info(f"Deleting expired lease {repr(lease)}")


    @loop(2)
    def loop(self):
        self.handle_new_leases()
        self.renew_leases()
