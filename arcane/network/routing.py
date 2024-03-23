from arcane.base_object import BaseObject
from arcane.network.network_interface import NetworkInterface
from arcane.exceptions import NoMatchingRouteException
from ipaddress import IPv4Address, IPv4Network
from scapy.all import IP

class NAT(object):
    def __call__(self, packet):
        return packet



class RoutingTable(BaseObject):
    def __init__(self) -> None:
        self.routes = []
    
    def add(self, network: IPv4Network, hop: IPv4Address, interface: NetworkInterface):
        self.routes.append(IPv4Network(network), hop, interface)
        self.routes.sort(key=lambda route: route[0].num_addresses)


    def __getitem__(self, destination_ip):
        return self.match(destination_ip)


    def match(self, destination_ip: IPv4Address):
        for network, hop, interface in self.routes:
            if destination_ip in network:
                return network, hop, interface

        raise NoMatchingRouteException


    def send(self, packet):
        try:
            _net, hop, interface = self[packet[IP].src]
            packet.src = interface.mac_address
            packet.dst = interface.arp_table[hop]
            interface.send(packet)
        except NoMatchingRouteException:
            self.log.info(f"No matching route; packet ({packet[IP].src}) -> ({packet[IP].dst}) dropped")


class Router(object):
    def __init__(self, interfaces: 'List[NetworkInterface]', routes: RoutingTable=None, translator: NAT=None) -> None:
        self.interfaces  = interfaces
        self.routes      = routes or RoutingTable()
        self.translator  = translator or NAT()
        self.subscribers = [interface.subscribe(self.handle_packet) for interface in interfaces]


    def handle_packet(self, packet):
        self.routes.send(self.translator(packet))

