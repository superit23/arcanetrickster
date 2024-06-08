from arcane.runtime import api, on_event
from arcane.threaded_worker import ThreadedWorker
from arcane.events import DHCPServerEvent, NetworkInterfaceEvent
from arcane.vpn.oracle import *
from scapy.all import DHCP, ARP

class VPNDetector(ThreadedWorker):
    def __init__(self):
        self.connections = {}
        self.detectors   = [d() for d in DestinationOracle.__subclasses__()]
        super().__init__()


    @on_event(NetworkInterfaceEvent.READ, lambda iface, proto, packet: DHCP not in packet and ARP not in packet)
    @api
    def listen_for_traffic(self, iface, proto, packet):
        for detector in self.detectors:
            if detector.detect(packet):
                proto = None
                if UDP in packet:
                    proto = UDP
                    
                elif TCP in packet:
                    proto = TCP
                
                src_port = None
                dst_port = None
                if proto:
                    src_port = packet[proto].sport
                    dst_port = packet[proto].dport

                self.connections[(packet.src, proto, src_port, dst_port)] = detector
