from arcane.events import DNSClientEvent
from arcane.event_manager import on_event, trigger_event
from arcane.threaded_worker import api
from arcane.dns.endpoint import DNSEndpoint
from dnslib.dns import DNSRecord, DNSError, QTYPE
from dnslib.digparser import DigParser
from scapy.all import Packet, DNS


class DNSClient(DNSEndpoint):
    def __init__(self, ns_ip: str="8.8.8.8") -> None:
        self.dns_cache = {}
        super().__init__(ns_ip)
    
    @api
    def send_query(self: "DNSClient", q_name: str, q_type: str, q_class: str='IN', bypass_cache: bool=False) -> None:
        query = DNSRecord.question(q_name, q_type, q_class)
        self.log.info(f"Handling query for {query.q.qname} : {QTYPE[query.q.qtype]} ")

        cache_key = (query.q.qname, query.q.qtype, query.q.qclass)

        if cache_key in self.dns_cache and not bypass_cache:
            return self.dns_cache[cache_key]

        response_packet:bytes = query.send(
            dest=self.ns_ip,
            port=self.port,
            tcp=self.tcp_bool
        )

        response:DNSRecord  = DNSRecord.parse(response_packet)
        if query.header.id != response.header.id:
            raise DNSError('Response transaction id does not match query transaction id')
        
        printable_answers = "\n".join([str(r) for r in response.rr])
        self.log.info(f"Response received for {query.q.qname} : {QTYPE[query.q.qtype]}\n{printable_answers}")
        self.dns_cache[cache_key] = response
        self.log.info(f"Caching the response for {query.q.qname} :  {QTYPE[query.q.qtype]}")
        trigger_event(DNSClientEvent.RESPONSE_RECEIVED, query, response)
        
