from arcane.events import NetworkInterfaceEvent, SocketEvent
from arcane.runtime import on_event, trigger_event, api, loop
from arcane.threaded_worker import ThreadedWorker
from scapy.all import UDP, IP, Raw
import socket


class UDPSocketManager(ThreadedWorker):
    def __init__(self, interface: "NetworkInterface") -> None:
        self.interface = interface
        self.sockets   = {}

        super().__init__()


    @api
    def add_socket(self, sock):
        key = sock.ip_address, sock.port

        if not key in self.sockets:
            self.sockets[key] = set()

        self.sockets[key].add(sock)
        return sock
    

    @api
    def delete_socket(self, sock: "UDPSocket"):
        key = sock.ip_address, sock.port
        if key in self.sockets:
            self.sockets[key].remove(sock)


    @on_event(NetworkInterfaceEvent.READ, lambda iface, proto, packet: UDP in packet)
    @api
    def recv(self, iface, proto, packet):
        src_ip, src_port = packet[IP].src, packet[UDP].sport
        dst_ip, dst_port = packet[IP].dst, packet[UDP].dport

        if iface == self.interface and UDP in packet and (dst_ip, dst_port) in self.sockets and Raw in packet:
            trigger_event(SocketEvent.READ, self, iface, UDP, (src_ip, src_port), (dst_ip, dst_port), packet.load)



class UDPSocket(object):
    def __init__(self, port: int, socket_manager: UDPSocketManager, ip_address: str=None):
        self.ip_address = ip_address or socket_manager.interface.ip_address
        self.port       = port
        self.socket_manager = socket_manager

        socket_manager.add_socket(self)


    def close(self):
        # TODO: Remove from socket manager
        self.socket_manager.delete_socket(self)


    def __del__(self):
        self.close()


    def send(self, data, dst_ip, dst_port):
        pkt = self.socket_manager.interface.build_packet(ip_address=self.ip_address, dst_ip=dst_ip)
        self.socket_manager.interface.send(pkt / UDP(src_port=self.port, dst_port=dst_port) / data)


    def matches_event(self, *event):
        event_type, _man, iface, proto, _src, (dst_ip, dst_port), _payload = event
        return (event_type, iface, proto, dst_ip, dst_port) == (SocketEvent.READ, self.socket_manager.interface, UDP, self.ip_address, self.dst_port)
