from arcane.threaded_worker import ThreadedWorker, api
from arcane.events import NetworkInterfaceEvent, ARPTableEvent
from arcane.event_manager import on_event, trigger_event, _event_man
from arcane.timer_manager import loop
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

    def __contains__(self, ip: str):
        return ip in self.table


    def get(self, ip: str, default: str=None):
        if ip in self:
            return self[ip]
        else:
            return default


    @api
    def get_or_ask(self, ip: str):
        mac = self.get(ip)
        if mac:
            return mac
        
        self.send_arp(ip)
        return _event_man.wait_for_match(ARPTableEvent.ENTRY_CHANGED, (lambda event, psrc, hwsrc: psrc == ip))


    def send_arp(self, ip: str):
        request = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=str(ip))
        self.interface.send(request)


    @loop(0.01)
    def _scan(self):
        sleep_time = self.sweep_time / self.interface.network.num_addresses
        for ip in self.interface.network:
            time.sleep(sleep_time)
            self.send_arp(ip)



    @on_event(NetworkInterfaceEvent.READ)
    @api
    def handle_packet(self, iface, packet):
        if ARP in packet:
            if not (packet.psrc in self.arp_table and self.arp_table[packet.psrc] == packet.hwsrc):
                self.arp_table[packet.psrc] = packet.hwsrc
                trigger_event(ARPTableEvent.ENTRY_CHANGED, packet.psrc, packet.hwsrc)

