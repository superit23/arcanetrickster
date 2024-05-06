from enum import Enum, auto

class RuntimeEvent(Enum):
    STATUS = auto()

class NetworkInterfaceEvent(Enum):
    READ  = auto()
    WRITE = auto()

class DHCPLeaseCollectorEvent(Enum):
    NEW_LEASE = auto()

class DHCPLeaseRenewerEvent(Enum):
    NEW_XID = auto()

class DHCPReleaseEvent(Enum):
    LEASE_RELEASED = auto()

class ARPTableEvent(Enum):
    ENTRY_CHANGED = auto()

class DHCPServerEvent(Enum):
    LEASE_OFFERED = auto()
    LEASE_DENIED  = auto()

class DNSClientEvent(Enum):
    QUERY_RECEIVED    = auto()
    RESPONSE_RECEIVED = auto()

class DNSServerEvent(Enum):
    QUERY_RECEIVED = auto()
    RESPONSE_SENT  = auto()