from arcane.core.events import DNSClientEvent
from arcane.core.runtime import on_event, trigger_event
from arcane.core.threaded_worker import api
from arcane.core.threaded_worker import ThreadedWorker
from dnslib.dns import DNSError, QTYPE
from arcane.dns.record import DNSRecord
from arcane.network.interface import NetworkInterface

class DNSClient(ThreadedWorker):
    def __init__(self, ns_ip: str="8.8.8.8",port: int=53, use_tcp: bool=False, timeout: float=0.5) -> None:
        self.dns_cache = {}
        self.ns_ip     = ns_ip
        self.use_tcp   = use_tcp
        self.port      = port
        self.timeout   = timeout
        super().__init__()


    @api
    def send_query(self: "DNSClient", query: DNSRecord, bypass_cache: bool=False) -> None:

        self.log.info(f"Handling query for {query.q.qname} : {QTYPE[query.q.qtype]} ")

        if query in self.dns_cache and not bypass_cache:
            trigger_event(DNSClientEvent.ANSWER_RECEIVED, query, self.dns_cache[query])

        else:
            # TODO: This is synchronous, should we make it async?
            response_packet:bytes = query.send(
                timeout=self.timeout,
                dest=self.ns_ip,
                port=self.port,
                tcp=self.use_tcp
            )

            response:DNSRecord = DNSRecord.parse(response_packet)
            trigger_event(DNSClientEvent.ANSWER_RECEIVED, self, response)
        
            self.dns_cache[query] = response
