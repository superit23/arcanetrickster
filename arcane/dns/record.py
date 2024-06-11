from dnslib.dns import DNSRecord as DNSLibRecord

class DNSRecord(DNSLibRecord):
    @property
    def cache_key(self):
        return (self.q.qname, self.q.qtype, self.q.qclass)


    def __hash__(self) -> int:
        return hash(self.cache_key)


    def __eq__(self, other):
        return type(self) == type(other) and self.cache_key == other.cache_key