from dnslib.dns import *
from threading import Event, Thread
from arcane.threaded_worker import ThreadedWorker

class DNSEndpoint(ThreadedWorker):
    def __init__(self: "DNSEndpoint", ns_ip:str = "8.8.8.8", port:int=53, tcp_bool:bool=False) -> None:
        self.ns_ip    = ns_ip
        self.port     = port
        self.tcp_bool = tcp_bool
        super().__init__()

    