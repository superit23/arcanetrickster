from arcane.core.base_object import BaseObject
from arcane.network.interface import NetworkInterface
from arcane.core.exceptions import NoMatchingRouteException
from arcane.core.runtime import on_event
from arcane.core.events import NetworkInterfaceEvent
from ipaddress import IPv4Address, IPv4Network
from copy import deepcopy
from scapy.all import IP


class NAT(object):
    def out(self, packet):
        return packet

    def in(self, packet):
        return packet

    def matches_in(self, packet):
        return True

    def matches_out(self, packet):
        return True


    def translate(self, packet):
        if self.matches_in(packet):
            return self.in(packet)

        else self.matches_out(packet):
            return self.out(packet)

        else:
            return packet


class BiMap(object):
    def __init__(self):
        self.forward  = {}
        self.backward = {}
    
    def __contains__(self, key):
        return key in self.forward or key in self.backward
    

    def __setitem__(self, key, value):
        self.forward[key]    = value
        self.backward[value] = key


    def __getitem__(self, key):
        if key in self.forward:
            return self.forward[key]

        elif key in self.backward:
            return self.backward[key]
        
        raise KeyError


    def __delete__(self, key):
        if key in self.forward:
            del self.forward[key]

        elif key in self.backwards:
            del self.backwards[key]
        
        raise KeyError


class PNAT(NAT):
    def __init__(self, nat_ip: IPv4Address, proto):
        self.nat_ip     = nat_ip
        self.proto      = proto
        self.conn_table = BiMap()
        self.used_ports = set()


    def get_free_port(self):
        for i in range(2**10, 2**16):
            if not i in self.used_ports:
                self.used_ports.add(i)
                return i
        
        raise ValueError("Ports exhausted")


    def get_out_params(self, packet):
        # Get sender info
        src_ip   = packet[IP].src
        src_port = packet[self.proto].sport

        return (packet[IP].src, packet[self.proto].sport)


    def track_connection(self, packet):
        trans_port  = self.get_free_port()
        conn_params = self.get_out_params(packet)

        self.conn_table[trans_port] = conn_params
        return trans_port


    def out(self, packet):
        conn_params = self.get_out_params(packet)

        try:
            trans_port = self.conn_table[conn_params]
        except KeyError:
            trans_port = self.track_connection(packet)


        mod_packet = deepcopy(packet)

        # Translate
        mod_packet[IP].src           = str(self.nat_ip)
        mod_packet[self.proto].sport = trans_port

        return mod_packet


    def in(self, packet):
        trans_port = packet[self.proto].dport
        client_ip, client_port, dst_ip, dst_port = self.conn_table[trans_port]
        
        mod_packet = deepcopy(packet)

        # Translate
        mod_packet[IP].dst      = client_ip
        mod_packet[proto].dport = client_port

        return mod_packet


    def matches_in(self, packet):
        return self.proto in packet and packet[self.proto].dport in self.conn_table.forward and packet[IP].dst == str(self.nat_ip)

    def matches_out(self, packet):
        return self.proto in packet and packet[IP].dst != str(self.nat_ip)



class DNAT(NAT):
    def __init__(self, ip_pool: 'List[IPv4Address]'):
        self.ip_pool     = ip_pool
        self.translation = BiMap()


    def create_translation(self, first: IPv4Address, second: IPv4Address):
        self.translation[first] = second


    def out(self, packet):
        real_dest  = self.translation[packet[IP].dst]
        mod_packet = deepcopy(packet)

        # Translate
        mod_packet[IP].dst = real_dest
        return mod_packet


    def in(self, packet):
        fake_dest  = self.translation[packet[IP].src]
        mod_packet = deepcopy(packet)

        # Translate
        mod_packet[IP].src = fake_dest
        return mod_packet


    def matches_in(self, packet):
        return packet[IP].src in self.translation

    def matches_out(self, packet):
        return packet[IP].dst in self.ip_pool



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
            self.log.debug(f"No matching route; packet ({packet[IP].src}) -> ({packet[IP].dst}) dropped")


class Router(object):
    def __init__(self, interfaces: 'List[NetworkInterface]', routes: RoutingTable=None) -> None:
        self.interfaces      = set(interfaces)
        self.routes          = routes or RoutingTable()
        self.translate_table = {}


    @on_event(NetworkInterfaceEvent.READ)
    def handle_packet_recv(self, iface, proto, packet):
        if iface in self.interfaces:
            # NATs MUST BE COMMUTATIVE
            nats = self.translate_table.get(iface, [])

            for nat in nats:
                packet = nat.translate(packet)

            self.routes.send(packet)
