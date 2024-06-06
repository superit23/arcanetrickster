from arcane.events import NetworkInterfaceEvent, SocketEvent
from arcane.runtime import on_event, trigger_event, api, loop
from arcane.threaded_worker import ThreadedWorker
from scapy.all import UDP
import socket

class UDPSocket(ThreadedWorker):
    def __init__(self, interface: "NetworkInterface", port: int, ip_address: str=None) -> None:
        self.interface  = interface
        self.ip_address = ip_address or interface.ip_address
        self.port       = port


    def send(self, data, dst_ip, dst_port):
        pkt = self.interface.build_packet(ip_address=self.ip_address, dst_ip=dst_ip)
        self.interface.send(pkt / UDP(src_port=self.port, dst_port=dst_port) / data)
    

    @on_event(NetworkInterfaceEvent.READ)
    @api
    def recv(self, iface, proto, packet):
        src_ip, src_port = packet[UDP].src_ip, packet[UDP].src_port
        dst_ip, dst_port = packet[UDP].dst_ip, packet[UDP].dst_port

        if iface == self.interface and UDP in packet and dst_ip == self.ip_address and dst_port == self.port:
            trigger_event(SocketEvent.READ, self, iface, UDP, (src_ip, src_port), (dst_ip, dst_port), bytes(packet.payload))


class NativeUDPSocket(ThreadedWorker):
    def __init__(self, interface: "NetworkInterface", port: int) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('', port))
        # self.socket.setblocking(0)

        self.interface = interface
        self.port = port
        super().__init__()


    def send(self, data, dst_ip, dst_port):
        self.socket.sendto(data, (dst_ip, dst_port))
    

    @loop(1e-3)
    def _recv_loop(self):
        data, src = self.socket.recvfrom(1024)
        trigger_event(SocketEvent.READ, self, self.interface, UDP, src, (self.interface.ip_address, self.port), data)
