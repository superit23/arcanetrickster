from arcane.threaded_worker import ThreadedWorker, api
from arcane.events import NetworkInterfaceEvent
from arcane.event_manager import on_event
from scapy.all import Ether, ARP
import time

class ARPTable(ThreadedWorker):
    def __init__(self, interface: 'NetworkInterface', sweep_time: int=30) -> None:
        self.interface  = interface
        self.table      = {}
        self.sweep_time = sweep_time
        super().__init__()
    

    def __getitem__(self, ip: str):
        return self.table[ip]


    def _run(self):
        while not self.event.is_set():
            sleep_time = self.sweep_time / self.interface.network.num_addresses
            for ip in self.interface.network:
                time.sleep(sleep_time)
                request = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=str(ip))
                self.interface.send(request)


    @on_event(NetworkInterfaceEvent.READ)
    @api
    def handle_packet(self, iface, packet):
        if ARP in packet:
            self.arp_table[packet.psrc] = packet.hwsrc

