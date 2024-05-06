from arcane.network.interface import NetworkInterface, VirtualInterface
from arcane.dhcp.server import DHCPServer
from arcane.dhcp.subleaser import DHCPSubleaser
from arcane.dhcp.range_leaser import DHCPRangeLeaser
from arcane.dhcp.releaser import DHCPReleaser
from arcane.dns.client import DNSClient
from arcane.registry import Registry
from arcane.runtime import RUNTIME
from arcane.events import DHCPLeaseCollectorEvent, DHCPServerEvent, DHCPLeaseRenewerEvent, ARPTableEvent, NetworkInterfaceEvent, DHCPReleaseEvent, RuntimeEvent
from ipaddress import IPv4Address
import time
import logging

logging.root.setLevel(logging.INFO)

# RUNTIME.event_manager.log_filter.allowlist_events.add(DHCPLeaseCollectorEvent.NEW_LEASE)
RUNTIME.event_manager.log_filter.allowlist_events.add(DHCPServerEvent.LEASE_OFFERED)
# RUNTIME.event_manager.log_filter.allowlist_events.add(DHCPLeaseRenewerEvent.NEW_XID)
RUNTIME.event_manager.log_filter.allowlist_events.add(ARPTableEvent.ENTRY_CHANGED)
RUNTIME.event_manager.log_filter.allowlist_events.add(DHCPReleaseEvent.LEASE_RELEASED)
RUNTIME.event_manager.log_filter.allowlist_events.add(RuntimeEvent.STATUS)
# RUNTIME.event_manager.log_filter.allowlist_events.add(NetworkInterfaceEvent.READ)

real_server = '10.10.10.1'
subnet_mask = "255.255.255.0"
enp0s3      = NetworkInterface("enp0s3")
routes      = [
    f"0.0.0.0/0:{enp0s3.ip_address}",
    f"8.8.8.8/32:{enp0s3.ip_address}"
]

options_routes = {
    "classless_static_routes": routes,
    "subnet_mask": subnet_mask
}

options_no_routes = {
    "router": enp0s3.ip_address,
    "subnet_mask": subnet_mask
}

server   = DHCPServer(enp0s3, DHCPSubleaser(enp0s3), **options_no_routes)
releaser = DHCPReleaser(enp0s3, server.lease_generator, real_server, sweep_time=5)

registry = Registry()
registry.register("enp0s3", enp0s3)
registry.register("server", server)
registry.register("releaser", releaser)

time.sleep(60)
server.options = options_routes


enp0s3.thread.join()



#server = DHCPServer(enp0s3, DHCPSubleaser(enp0s3), **options)

#releaser = DHCPReleaser(enp0s3, server.lease_generator, '10.10.10.1', sweep_time=5)
# releaser = DHCPReleaser(enp0s3, DHCPRangeLeaser(enp0s3, IPv4Address("10.10.10.10"), IPv4Address("10.10.10.239")), '10.10.10.1', sweep_time=5)
#eth0   = NetworkInterface("eth0")

#enp0s8 = NetworkInterface("enp0s8")

# server = DHCPServer(enp0s3, DHCPRangeLeaser(enp0s3, IPv4Address("10.10.10.10"), IPv4Address("10.10.10.239")), **options_no_routes)

#server   = DHCPServer(enp0s3, DHCPSubleaser(enp0s3))

# dns_client = DNSClient()
# dns_client.send_query("amazon.com", "A")

# dns_client.thread.join()
# enp0s3.arp_table._scan()