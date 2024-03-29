from arcane.dhcp.lease_generator import DHCPLeaseGenerator
from arcane.network.interface import NetworkInterface
from arcane.dhcp.lease_collector import DHCPLeaseCollector
from arcane.dhcp.lease_renewer import DHCPLeaseRenewer

class DHCPSubleaser(DHCPLeaseGenerator):
    def __init__(self, interface: NetworkInterface) -> None:
        self.renewer   = DHCPLeaseRenewer(interface)
        self.collector = DHCPLeaseCollector(interface)
        self.interface = interface
        super().__init__()


    @property
    def leases(self):
        return self.renewer.leases
