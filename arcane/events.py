from enum import Enum, auto


class NetworkInterfaceEvent(Enum):
    READ = auto()

class DHCPLeaseCollectorEvent(Enum):
    NEW_LEASE = auto()

class DHCPLeaseRenewerEvent(Enum):
    NEW_XID = auto()

class DHCPReleaseEvent(Enum):
    LEASE_RELEASED = auto()
