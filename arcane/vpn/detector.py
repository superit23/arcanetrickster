from arcane.runtime import api, on_event, trigger_event
from arcane.threaded_worker import ThreadedWorker
from arcane.events import DHCPServerEvent, NetworkInterfaceEvent, VPNDetectorEvent, SocketEvent
from arcane.network.socket_manager import UDPSocket, UDPSocketManager
from arcane.vpn.oracle import *
from scapy.all import DHCP, UDP, IP

class VPNDetector(ThreadedWorker):
    def __init__(self, interface: "NetworkInterface"):
        self.connections = {}
        self.detectors   = [d for d in Detector.__subclasses__()]
        self.interface   = interface

        self.sock_man = UDPSocketManager(interface)
        super().__init__()


    @on_event(NetworkInterfaceEvent.READ, lambda iface, proto, packet: DHCP not in packet and UDP in packet)
    @api
    def listen_for_new_udp(self, iface, proto, packet):
        if iface != self.interface:
            return

        dst_ip, dst_port = packet[IP].dst, packet[UDP].dport
        if not (dst_ip, dst_port) in self.connections:
            self.log.debug(f"Adding new UDP connection {(dst_ip, dst_port)}")
            sock = UDPSocket(ip_address=dst_ip, port=dst_port, socket_manager=self.sock_man)
            self.connections[(dst_ip, dst_port)] = (False, sock, [d() for d in self.detectors])


    @on_event(SocketEvent.READ, lambda _sock_man, _iface, proto, _src, _dst, payload: proto == UDP)
    def handle_udp_traffic(self, sock_man, iface, proto, src, dst, payload):
        if not dst in self.connections:
            return

        found, sock, detectors = self.connections[dst]

        # Don't double process
        if found:
            return

        # Detect VPN traffic
        to_remove = set()
        for idx, detector in enumerate(detectors):
            detector.process_packet(payload)

            if detector.has_completed:
                if detector.is_detected:
                    found = True
                    break
                else:
                    to_remove.add(detector)


        # Prune bad detectors
        if found:
            self.connections[dst] = (found, sock, [detector])
            trigger_event(VPNDetectorEvent.VPN_FOUND, sock, detector)
        else:
            self.connections[dst] = (found, sock, [d for d in detectors if d not in to_remove])
