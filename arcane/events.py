from enum import Enum, auto

class RuntimeEvent(Enum):
    STATUS = auto()

class NetworkInterfaceEvent(Enum):
    READ  = auto()
    WRITE = auto()
    RESOURCE_UNAVAILABLE = auto()

class DHCPLeaseCollectorEvent(Enum):
    NEW_LEASE = auto()

class DHCPLeaseRenewerEvent(Enum):
    NEW_XID = auto()

class DHCPReleaseEvent(Enum):
    LEASE_RELEASED = auto()

class ARPTableEvent(Enum):
    ENTRY_CHANGED = auto()

class DHCPServerEvent(Enum):
    LEASE_OFFERED  = auto()
    LEASE_DENIED   = auto()
    LEASE_ACCEPTED = auto()

class DNSClientEvent(Enum):
    ANSWER_RECEIVED  = auto()
    TIMEOUT_RECEIVED = auto()

class DNSResolverEvent(Enum):
    ANSWER_RECEIVED  = auto()
    TIMEOUT_RECEIVED = auto()

class DNSServerEvent(Enum):
    QUERY_RECEIVED   = auto()
    ADD_LOCAL_RECORD = auto()
    RESPONSE_SENT    = auto()


class SocketEvent(Enum):
    OPEN  = auto()
    READ  = auto()
    WRITE = auto()


class VPNDetectorEvent(Enum):
    VPN_FOUND = auto()
