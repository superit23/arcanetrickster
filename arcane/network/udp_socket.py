from arcane.core.events import NetworkInterfaceEvent, SocketEvent
from arcane.core.runtime import on_event, trigger_event, api, loop
from arcane.core.threaded_worker import ThreadedWorker

from arcane.network.interface import NetworkInterface
from scapy.all import UDP
import socket


class NativeUDPSocket(ThreadedWorker):
    def __init__(self, iface: "NetworkInterface", port: int) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('', port))

        self.interface = iface
        self.port = port
        super().__init__()


    def send(self, data, dst_ip, dst_port):
        self.socket.sendto(data, (dst_ip, dst_port))
    

    @loop(1e-3)
    def _recv_loop(self):
        data, src = self.socket.recvfrom(1024)
        trigger_event(SocketEvent.READ, self, self.interface, UDP, src, (self.interface.ip_address, self.port), data)
