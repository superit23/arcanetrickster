from arcane.threaded_worker import ThreadedWorker
from arcane.events import NetworkInterfaceEvent, DHCPLeaseRenewerEvent, DHCPReleaseEvent, DHCPLeaseCollectorEvent
from arcane.runtime import loop, on_event, trigger_event, api
from arcane.utilities import random_mac
from arcane.network.interface import NetworkInterface
from arcane.dhcp.lease import DHCPLease, build_packet_base
from scapy.all import DHCP, BOOTP, IP, Ether, UDP
import random

class DHCPLeaseCollector(ThreadedWorker):
    def __init__(self, interface: NetworkInterface) -> None:
        self.interface       = interface
        self.server_ip       = None
        self.server_mac      = None
        self.recent          = set()
        self.virtual_clients = {}
        self.xid_map         = {}
        super().__init__()


    @on_event(DHCPLeaseRenewerEvent.NEW_XID)
    @api
    def handle_external_xid(self, xid, mac):
        self.xid_map[xid] = mac


    @on_event(NetworkInterfaceEvent.READ)
    @api
    def handle_offer_callback(self, iface, proto, data):
        if DHCP in data and data[BOOTP].xid in self.xid_map:
            self.log.debug(f"Creating lease: MAC: {data.dst}, IP: {data[BOOTP].yiaddr}, Options: {data[DHCP].options}")

            # Grab server info on first packet
            if not self.server_ip:
                self.server_ip  = data[IP].src
                self.server_mac = data.src


            mac = self.xid_map[data[BOOTP].xid]
            del self.xid_map[data[BOOTP].xid]

            options = DHCPLease.parse_options(data[DHCP].options)

            lease = DHCPLease(
                mac,
                data[BOOTP].yiaddr,
                data.src,
                data[BOOTP].siaddr,
                options,
                options['lease_time']
            )

            self.virtual_clients[mac] = lease

            trigger_event(DHCPLeaseCollectorEvent.NEW_LEASE, lease)
            self.interface.send(lease.build_request_packet(data[BOOTP].xid))


    @on_event(DHCPReleaseEvent.LEASE_RELEASED)
    def handle_lease(self, lease):
        self._loop()


    @loop(0.25)
    def _loop(self):
        xid   = random.randint(0, 2**32-1)
        lease = None
        if len(self.virtual_clients) < self.interface.network.num_addresses:
            mac = random_mac()
            self.virtual_clients[mac] = None
        else:
            # Look for virtual clients with expired leases
            found = False
            for mac, lease in self.virtual_clients.items():
                if not lease or lease.is_expired:
                    found = True
                    break

            if not found:
                return


        # Let the lease ask for the same IP if possible
        if lease:
            packet = lease.build_discover_packet(xid=xid)
        else:
            packet = build_packet_base(xid=xid, op=1, src_mac=mac) / DHCP(options=[("message-type", "discover"), ("end")])

        self.xid_map[xid] = mac
        self.interface.send(packet)
        self.log.debug(f"Sending discover. XID: {hex(xid)}, MAC: {mac}")
