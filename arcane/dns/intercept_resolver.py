from dnslib.dns import *
from arcane.core.events import DNSResolverEvent,DNSClientEvent
from arcane.core.runtime import on_event,trigger_event
from arcane.core.threaded_worker import api, ThreadedWorker
from arcane.dns.client import DNSClient

class DNSInterceptResolver(ThreadedWorker):

    def __init__(self: "DNSInterceptResolver", client_timeout: float=0.5) -> None:
        self.local_records = {}
        self.dns_client = DNSClient(timeout=client_timeout)
        super().__init__()


    @on_event(DNSClientEvent.ANSWER_RECEIVED)
    @api
    def send_response(self: "DNSInterceptResolver", dns_client: DNSClient, record: DNSRecord)-> None: 
        if dns_client == self.dns_client:
            trigger_event(DNSResolverEvent.ANSWER_RECEIVED, self, record)


    @api
    def record_lookup(self: "DNSInterceptResolver", query: DNSRecord) -> None: 
        if query in self.local_records:
            trigger_event(DNSResolverEvent.ANSWER_RECEIVED, self, self.local_records[query])

        else:
           self.dns_client.send_query(query)


    @api
    def add_local_record(self: "DNSInterceptResolver", record: DNSRecord, force_update: bool=True):
        if force_update or not record in self.local_records:
            self.local_records[record] = record


    @api
    def delete_local_record(self: "DNSInterceptResolver", record: DNSRecord):
        if record in self.local_records:
            del self.local_records[record]
