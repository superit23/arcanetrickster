from arcane.threaded_worker import ThreadedWorker, api
from arcane.network.arp_table import ARPTable
from arcane.event_manager import trigger_event, _event_man
from arcane.timer_manager import loop
from arcane.events import NetworkInterfaceEvent
from arcane.network.linux import KernelInterface
from scapy.all import Ether, get_if_hwaddr, get_if_addr, conf, ltoa
from ipaddress import IPv4Address, IPv4Network, NetmaskValueError
from pyroute2 import NDB as Ndb

import select
import socket

NDB = Ndb(log='info')

class NetworkInterface(ThreadedWorker, KernelInterface):
    '''This class creates a virtual network interface and a non-binding socket. 
        It uses a subscriber model to enable multi-threading.
    '''

    def __init__(self, name: str, sock=None) -> None:
        self.name = name

        if sock:
            self.socket = sock
        else:
            # Create Socket and bind it
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            self.socket.bind((self.name, 0x0800))

            # Set socket to non-binding to allow for multi-threading without lockup
            self.socket.setblocking(0)
            self.set_promiscious()

        self.arp_table = ARPTable(self)
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


    def close(self):
        ''' Sets Event flag to break while loop in _run() function. 
            Closes the socket and has the thread for the 
            network interface rejoin main python thread.
        '''
        self.event.set()
        self.socket.close()
        self.thread.join()


    def send(self, data: bytes):
        '''Sends data in bytes over the socket.'''
        self.socket.send(bytes(data))
        trigger_event(NetworkInterfaceEvent.WRITE, self, data)


    @loop(1e-3)
    def _loop(self):
        r, _w, _err = select.select([self.socket], [], [], 10e-3)

        if self.socket in r:
            data = self.socket.recv(4 * 1024)
            trigger_event(NetworkInterfaceEvent.READ, self, Ether(data))


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
    def handle_packet(self, iface, packet):
        print("Wowee")
        if iface in self.attached_interfaces:
            print("oh boy!")
            self.socket.dev.write(bytes(packet))


    def attach(self, interface: NetworkInterface):
        self.attached_interfaces.add(interface)
        _event_man.subscribe(NetworkInterfaceEvent.READ, self.handle_packet)


class Bridge(object):
    def __init__(self, name: str):
        self.name = name
        NDB.interfaces.create(ifname=self.name, kind='bridge').commit()

    
    def add_port(self, name: str):
        with NDB.interfaces[name] as net_if:
            net_if.set('master', NDB.interfaces[self.name]['index'])

    def remove_port(self, name: str):
        with NDB.interfaces[name] as net_if:
            net_if.set('master', 0)
