import time
import random
from scapy.all import Ether, IP, UDP, BOOTP, DHCP
from arcane.base_object import BaseObject
from copy import copy


def build_packet_base(op, xid: int=None, siaddr: int=None, ciaddr: int=None, secs: int=0, src_ip: str=None, dst_mac: str=None, dst_ip: str=None, yiaddr: str=None, chaddr: str=None, src_mac: str=None):
    if op == 1:
        sport, dport = 68, 67
    else:
        sport, dport = 67, 68
    
    ANY_IP = '0.0.0.0'
    ALL_IP = '255.255.255.255'

    mac_bytes = int.to_bytes(int((chaddr or src_mac).replace(":", ""), 16), 6, 'big')
    packet    = Ether(dst=dst_mac or 'ff:ff:ff:ff:ff:ff', src=src_mac, type=0x0800) \
        / IP(src=src_ip or ANY_IP, dst=dst_ip or ALL_IP) \
        / UDP(dport=dport, sport=sport) \
        / BOOTP(op=op, secs=secs, chaddr=mac_bytes, xid=xid or random.randint(0, 2**32-1), 
                siaddr=siaddr or ANY_IP, ciaddr=ciaddr or ANY_IP, yiaddr=yiaddr or ANY_IP)#, flags="B")

    return packet 


class DHCPLease(BaseObject):
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


    @staticmethod
    def parse_options(options, strip_type: bool=True):
        return dict([(k,v) for k,v in [o for o in options if o not in ("end", "pad")] if not strip_type or k != "message-type"])


    @staticmethod
    def parse_client_ip(packet):
        if packet[IP].src == "0.0.0.0":
            if packet[BOOTP].ciaddr == '0.0.0.0':
                lease_ip = [opt for opt in packet[DHCP].options if opt[0] == "requested_addr"][0][1]
            else:
                lease_ip = packet[BOOTP].ciaddr
        else:
            lease_ip = packet[IP].src
        
        return lease_ip



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


    def client_base_kwargs(self):
        return {"src_mac": self.mac_address, "dst_mac": self.server_mac, "src_ip": self.ip_address, "dst_ip": self.server_ip}


    def build_discover_packet(self, xid=None):
        return build_packet_base(1, xid, **self.client_base_kwargs()) / DHCP(options=[("message-type", "discover"), ("requested_addr", self.ip_address), ("end")])


    def build_request_packet(self, xid):
        return build_packet_base(1, xid, **self.client_base_kwargs()) / DHCP(options=[("message-type", "request"), ("requested_addr", self.ip_address), ("server_id", self.server_ip), ("end")])


    def build_renewal_packet(self, xid=None):
        return build_packet_base(1, xid, ciaddr=self.ip_address, secs=1, **self.client_base_kwargs()) / DHCP(options=[("message-type", "request"), ("end")])


    def build_ack_packet(self, xid, dst_mac, dst_ip, siaddr, yiaddr, src_ip, ciaddr='0.0.0.0'):
        options = copy(self.options)
        if "server_id" in options:
            del options['server_id']

        return build_packet_base(2, xid, dst_mac=dst_mac, dst_ip=dst_ip, src_ip=src_ip, siaddr=siaddr, chaddr=dst_mac, yiaddr=yiaddr, ciaddr=ciaddr) / DHCP(options=[("message-type", "ack"), ("server_id", siaddr), *list(options.items()), ("end")])


    @staticmethod
    def build_nak_packet(xid, dst_mac, dst_ip, src_ip):
        return build_packet_base(2, xid, dst_mac=dst_mac, dst_ip=dst_ip, src_ip=src_ip, chaddr=dst_mac) / DHCP(options=[("message-type", "nak"), ("end")])


    def build_offer_packet(self, xid, dst_mac, dst_ip, siaddr, yiaddr):
        options = copy(self.options)
        if "server_id" in options:
            del options['server_id']

        return build_packet_base(2, xid, dst_mac=dst_mac, dst_ip=dst_ip, siaddr=siaddr, yiaddr=yiaddr, chaddr=dst_mac) / DHCP(options=[("message-type", "offer"), ("server_id", siaddr), *list(options.items()), ("end")])


    def build_release_packet(self):
        return build_packet_base(1, ciaddr=self.ip_address, **self.client_base_kwargs()) / DHCP(options=[("message-type", "release"), ("server_id", self.server_ip), *list(self.options.items()), ("end")])
