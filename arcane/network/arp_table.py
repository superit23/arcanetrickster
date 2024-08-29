from arcane.core.threaded_worker import ThreadedWorker, api
from arcane.core.events import NetworkInterfaceEvent, ARPTableEvent
from arcane.core.runtime import on_event, trigger_event, loop, RUNTIME
from scapy.all import Ether, ARP
import time

class ARPTable(ThreadedWorker):
    def __init__(self, interface: 'NetworkInterface', sweep_time: int=10) -> None:
        self.interface  = interface
        self.table      = {}
        self.sweep_time = sweep_time
        self.last_sweep = 0
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
        return RUNTIME.event_manager.wait_for_match(ARPTableEvent.ENTRY_CHANGED, (lambda event, psrc, hwsrc: psrc == ip), timeout=0.1)


    @api
    def send_arp(self, ip: str):
        request = Ether(src=self.interface.mac_address, dst='ff:ff:ff:ff:ff:ff')/ARP(psrc=self.interface.ip_address, pdst=str(ip))
        self.interface.send(request)


    @loop(3)
    def _scan(self):
        if time.time() - self.last_sweep >= self.sweep_time and self.interface.is_up() and self.interface.subnet_mask:
            sleep_time      = self.sweep_time / self.interface.network.num_addresses
            self.last_sweep = time.time()
            for idx, ip in enumerate(self.interface.network):
                self.send_arp(ip, do_after=sleep_time*idx)


    @on_event(NetworkInterfaceEvent.READ, lambda iface, proto, packet: ARP in packet)
    @api
    def handle_packet(self, iface, proto, packet):
        if not (packet.psrc in self.table and self.table[packet.psrc] == packet.hwsrc):
            self.table[packet.psrc] = packet.hwsrc
            trigger_event(ARPTableEvent.ENTRY_CHANGED, packet.psrc, packet.hwsrc)
