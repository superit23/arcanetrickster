from arcane.events import DNSResolverEvent, SocketEvent
from arcane.threaded_worker import ThreadedWorker
from arcane.runtime import on_event
from arcane.threaded_worker import api
from arcane.dns.intercept_resolver import DNSInterceptResolver
from arcane.network.interface import NetworkInterface
from arcane.network.udp_socket import NativeUDPSocket
from arcane.dns.record import DNSRecord
from scapy.all import DNS

class DNSServer(ThreadedWorker):

    def __init__(self: "DNSServer", iface: NetworkInterface, ns_ip: str="8.8.8.8", port: int=53, use_tcp: bool=False, custom_resolver: DNSInterceptResolver=DNSInterceptResolver()) -> None:
        self.query_map  = {}
        self.resolver   = custom_resolver
        self.ns_ip      = ns_ip
        self.port       = port
        self.use_tcp    = use_tcp
        self.socket     = NativeUDPSocket(iface=iface, port=self.port)
        super().__init__()


    @on_event(SocketEvent.READ)
    @api
    def handle_packet(self: "DNSServer", socket, iface, proto, src, dst, data) -> None:
        if socket == self.socket and DNS(data).opcode == 0:
            query = DNSRecord.parse(data)
            self.query_map[query] = src
            self.resolver.record_lookup(query)


    @on_event(DNSResolverEvent.ANSWER_RECEIVED)
    @api
    def respond(self: "DNSServer", dns_resolver: DNSInterceptResolver, record: DNSRecord) -> None:
        if dns_resolver == self.resolver:
            response = record.pack()

            src = self.query_map[record]
            del self.query_map[record]

            self.socket.send(response, *src)
