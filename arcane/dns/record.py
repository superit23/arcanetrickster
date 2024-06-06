from dnslib.dns import DNSRecord as DNSLibRecord

class DNSRecord(DNSLibRecord):

    def __hash__(self) -> int:
        return hash((self.q.qname, self.q.qtype, self.q.qclass))


    def __eq__(self, other):
        return type(self) == type(other) and (self.q.qname, self.q.qtype, self.q.qclass) == (other.q.qname, other.q.qtype, other.q.qclass)
