
class DestinationOracle(object):
    def detect(self, packet):
        return False

    def analyze(self, packet):
        return False


class WireguardOracle(DestinationOracle):
    def detect(self, packet):
        if not UDP in packet:
            return False
        
        header = wg_hdr.from_buffer_copy(packet.load)
        return header.type in (1,2,3,4) and bytes(header.reserved) == b'\x00\00\x00'

    # 0x04 is the data channel
    def analyze(self, packet):
        return packet.load[0] == 4


class OpenVPNOracle(DestinationOracle):
    # https://build.openvpn.net/doxygen/network_protocol.html
    # https://github.com/corelight/zeek-spicy-openvpn/blob/master/analyzer/analyzer.spicy

    def detect(self, packet):
        return UDP in packet and packet[UDP].dport == 1194

    # Data channel is UDP
    def analyze(self, packet):
        return UDP in packet and (packet.load[0] >> 3) in (6,9)


# ExpressVPN
class LightwayOracle(DestinationOracle):
    def detect(self, packet):
        if not UDP in packet:
            return False

        header = he_wire_hdr.from_buffer_copy(packet.load)
        # Futureproof by setting max major version to 4
        return header.he == b'He' and bytes(header.reserved) == b'\x00\00\x00' and header.major_version < 5


    def analyze(self, packet):
        return False




class WireguardDetector(object):
    def __init__(self):
        self.bad_packet = False
        self.points     = 0
        self.threshold  = 50

        self.sources      = set()
        self.destinations = []
        self.dest_ctrs    = {}
    

    @property
    def is_detected(self):
        return not self.bad_packet and self.points > self.threshold


    def process_packet(self, packet):
        data = packet.load
        hdr  = wg_hdr.from_buffer_copy(data)

        if hdr.type == 1:
            body = wg_initiate.from_buffer_copy(data[4:])
        elif hdr.type == 2:
            body = wg_respond.from_buffer_copy(data[4:])
        elif hdr.type == 3:
            body = wg_cookie.from_buffer_copy(data[4:])
        elif hdr.type == 4:
            body = wg_transport.from_buffer_copy(data[4:])
        else:
            self.bad_packet = True
            return

        
        return hdr, body


    def handle_initiate(self, hdr, body):
        if body != sizeof(wg_initiate):
            self.bad_packet = True
            return
        
        self.points += 10
        if body.mac2 == [0]*16:
            self.points += 10
        
        self.sources.add(tuple(body.sender))


    def handle_respond(self, hdr, body):
        if body != sizeof(wg_respond):
            self.bad_packet = True
            return
        
        self.points += 10
        if body.mac2 == [0]*16:
            self.points += 10

        self.destinations.add(tuple(self.destination))
        if body.sender in self.sources:
            self.points += 10

        self.sources.add(tuple(body.sender))
    
        if body.mac2 == [0]*16:
            self.points += 10


    def handle_transport(self, hdr, body: wg_transport):
        if body.receiver in self.sources or body.receiver in self.destinations:
            self.points += 10

        # This is a little endian counter.
        # This is true as long as they haven't sent 2^40 packets over the VPN
        if body.counter[5:] == [0]*3:
            self.points += 5
        
        receiver = int.from_bytes(body.receiver, 'little')
        counter  = int.from_bytes(body.counter, 'little')
        if body.receiver in self.dest_ctrs:
            if self.dest_ctrs[receiver] + 1 == counter:
                self.points += 10
            
        
        self.dest_ctrs[receiver] = counter