
# https://stackoverflow.com/questions/6067405/python-sockets-enabling-promiscuous-mode-in-linux
import ctypes
import select
import socket
import fcntl
from arcane.threaded_worker import ThreadedWorker
from arcane.network.arp_table import ARPTable
from arcane.event_manager import trigger_event
from arcane.events import NetworkInterfaceEvent
from scapy.all import Ether, get_if_hwaddr, get_if_addr, conf, ltoa
from ipaddress import IPv4Address, IPv4Network


class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]



class NetworkInterface(ThreadedWorker):
    '''This class creates a virtual network interface and a non-binding socket. 
        It uses a subscriber model to enable multi-threading.
    '''

    def __init__(self, name: str) -> None:
        self.name   = name
        # Create Socket and bind it
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.socket.bind((self.name, 0x0800))
        # Set socket to non-binding to allow for multi-threading without lockup
        self.socket.setblocking(0)
        self.enter_promiscious_mode()

        self.arp_table = ARPTable(self)
        super().__init__()


    def enter_promiscious_mode(self):
        IFF_PROMISC  = 0x100
        SIOCGIFFLAGS = 0x8913
        SIOCSIFFLAGS = 0x8914

        ifr = ifreq()
        ifr.ifr_ifrn = self.name.encode('utf-8')
        fcntl.ioctl(self.socket.fileno(), SIOCGIFFLAGS, ifr)
        ifr.ifr_flags |= IFF_PROMISC
        fcntl.ioctl(self.socket.fileno(), SIOCSIFFLAGS, ifr)


    @property
    def mac_address(self):
        '''
        Returns the scapy MAC address.
        '''
        return get_if_hwaddr(self.name)


    @property
    def ip_address(self):
        '''
        Return the scapy IP address 
        '''
        return get_if_addr(self.name)


    @property
    def subnet_mask(self):
        for net, msk, gw, iface, addr, metric in conf.route.routes:
            if iface == self.name:
                network = IPv4Network(f"{ltoa(net)}/{ltoa(msk)}")
                if IPv4Address(self.ip_address) in network and gw == '0.0.0.0':
                    return ltoa(msk)


    @property
    def network(self):
        return IPv4Network(f"{self.ip_address}/{self.subnet_mask}", strict=False)


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
        trigger_event(NetworkInterfaceEvent.WRITE, self.name, data)


    def _run(self):
        while not self.event.is_set():
            r, _w, _err = select.select([self.socket], [], [], 1e-5)

            if self.socket in r:
                data = self.socket.recv(4 * 1024)
                trigger_event(NetworkInterfaceEvent.READ, self.name, Ether(data))

