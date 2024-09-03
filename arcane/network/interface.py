from arcane.core.threaded_worker import ThreadedWorker, api
from arcane.network.arp_table import ARPTable
from arcane.core.runtime import loop, trigger_event
from arcane.core.events import NetworkInterfaceEvent
from arcane.network.linux import KernelInterface
from scapy.all import Ether, get_if_hwaddr, get_if_addr, ltoa, fragment
from ipaddress import IPv4Network, NetmaskValueError
from queue import Queue
from scapy.all import Ether, get_if_hwaddr, get_if_addr, ltoa, IP
from ipaddress import IPv4Network, NetmaskValueError
from queue import Queue
from enum import Enum
from pyroute2 import NDB as Ndb

import select
import socket

NDB = Ndb(log='info')

class Proto(Enum):
    IP  = 0x0800
    ARP = 0x0806

def create_raw_socket(name: str, proto: Proto):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((name, proto.value))

    # Set socket to non-binding to allow for multi-threading without lockup
    # sock.setblocking(0)
    return sock


class NetworkInterface(ThreadedWorker, KernelInterface):
    '''This class creates a virtual network interface and a non-binding socket. 
        It uses a subscriber model to enable multi-threading.
    '''

    def __init__(self, name: str, sock=None, auto_fragment: bool=False) -> None:
        self.name = name

        if sock:
            self.socket = sock
        else:
            # Create Socket and bind it
            self.socket = create_raw_socket(self.name, Proto.IP)
            self.set_promiscious()
        
        self.arp_socket    = create_raw_socket(self.name, Proto.ARP)
        self.arp_table     = ARPTable(self, sweep_time=100)
        self.send_queue    = Queue()
        self.auto_fragment = auto_fragment
        super().__init__()


    def set_ipaddress(self, ip_cidr: str):
        with NDB.interfaces[self.name] as net_if:
            net_if.add_ip(ip_cidr)
    

    def set_mac(self, mac: str):
        with NDB.interfaces[self.name] as net_if:
            net_if['address'] = mac


    def set_up(self):
        with NDB.interfaces.wait(ifname=self.name) as net_if:
            net_if.set('state', 'up')


    def set_down(self):
        with NDB.interfaces[self.name] as net_if:
            net_if.set('state', 'down')

    def is_up(self):
        try:
            return NDB.interfaces[self.name].get("state") == 'up'
        except KeyError:
            return False


    @property
    def fd(self):
        return self.socket.fileno()


    @property
    def mac_address(self):
        '''
        Returns the MAC address
        '''
        try:
            return get_if_hwaddr(self.name)
        except:
            pass


    @property
    def ip_address(self):
        '''
        Returns the IP address 
        '''
        try:
            return get_if_addr(self.name)
        except:
            pass


    @property
    def subnet_mask(self):
        try:
            for ip_info in NDB.interfaces[self.name].ipaddr.values():
                if ip_info['family'] == socket.AF_INET:
                    prefix = int(ip_info['prefixlen'])
                    return ltoa(2**32-2**(32-prefix))
        except KeyError:
            pass


    @property
    def network(self):
        try:
            return IPv4Network(f"{self.ip_address}/{self.subnet_mask}", strict=False)
        except NetmaskValueError:
            pass
    

    @property
    def default_gateway(self):
        for r in NDB.routes.summary():
            if r['ifname'] == self.name and r['dst_len'] == 0:
                return r['gateway']


    def close(self):
        ''' Sets Event flag to break while loop in _run() function. 
            Closes the socket and has the thread for the 
            network interface rejoin main python thread.
        '''
        self.event.set()
        self.socket.close()
        self.thread.join()
    

    def build_packet(self, mac_address: str=None, ip_address: str=None, dst_mac: str=None, dst_ip: str=None):
        if not dst_mac:
            gw = self.default_gateway
            if gw:
                dst_mac = self.arp_table[gw]

        return Ether(src_mac=mac_address or self.mac_address, dst_mac=dst_mac) / IP(src=ip_address or self.ip_address, dst_ip=dst_ip)


    def send(self, data: bytes, should_fragment: bool=False):
        '''Sends data in bytes over the socket.'''
        if (self.auto_fragment or should_fragment) and IP in data:
            for pkt in fragment(data):
                self.send_queue.put(bytes(pkt))
        else:
            self.send_queue.put(bytes(data))


    @loop(1e-3)
    def _loop(self):
        for _ in range(50):
            r, _w, _err = select.select([self.socket, self.arp_socket], [], [], 1e-4)

            if not r:
                break

            if self.socket in r:
                data = self.socket.recv(4 * 1024)
                trigger_event(NetworkInterfaceEvent.READ, self, Proto.IP, Ether(data))

            if self.arp_socket in r:
                data = self.arp_socket.recv(4 * 1024)
                trigger_event(NetworkInterfaceEvent.READ, self, Proto.ARP, Ether(data))


        for _ in range(50):
            if self.send_queue.empty():
                break

            data = self.send_queue.get()
            self.socket.send(data)


class VirtualSocket(object):
    def __init__(self, dev):
        self.dev = dev
    
    def fileno(self):
        return self.dev.fileno()

    def recv(self, bufsize):
        return self.dev.read(bufsize)

    def send(self, bytes):
        self.dev.write(bytes)

    def close(self):
        self.dev.close()

    def __del__(self):
        self.close()


class VirtualInterface(NetworkInterface):
    def __init__(self, name: str):
        self.name   = name
        self.socket = VirtualSocket(open("/dev/net/tun", "r+b", buffering=0))
        self.set_tap()
        self.set_up()
        self.attached_interfaces = set()

        super().__init__(name=name, sock=self.socket)


    @api
    def handle_packet(self, iface, proto, packet):
        if iface in self.attached_interfaces:

            self.socket.dev.write(bytes(packet))


    def attach(self, interface: NetworkInterface):
        self.attached_interfaces.add(interface)
        # TODO Replace this _event_man does not exist anymore in the code.
        _event_man.subscribe(NetworkInterfaceEvent.READ, self.handle_packet)
