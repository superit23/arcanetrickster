from arcane.vpn.packet import wg_hdr, wg_initiate, wg_respond, wg_cookie, wg_transport, he_wire_hdr

# class OpenVPNOracle(DestinationOracle):
#     # https://build.openvpn.net/doxygen/network_protocol.html
#     # https://github.com/corelight/zeek-spicy-openvpn/blob/master/analyzer/analyzer.spicy

#     def detect(self, packet):
#         return UDP in packet and packet[UDP].dport == 1194

#     # Data channel is UDP
#     def analyze(self, packet):
#         return UDP in packet and (packet.load[0] >> 3) in (6,9)




class Detector(object):
    @property
    def has_completed(self):
        return self.bad_packet or self.points >= self.threshold

    @property
    def is_detected(self):
        return not self.bad_packet and self.points >= self.threshold

    @property
    def can_filter_datachannel(self):
        return True

    def is_datachannel_packet(self, packet):
        raise NotImplementedError

    def process_packet(self, packet):
        raise NotImplementedError


class WireguardDetector(Detector):
    """
    Detects the Wireguard protocol in 2-5 packets, depending on the number of sources/destinations.
    """

    def __init__(self):
        self.bad_packet = False
        self.points     = 0
        self.threshold  = 50

        self.sources      = set()
        self.destinations = set()
        self.dest_ctrs    = {}


    def process_packet(self, data):
        hdr       = wg_hdr.from_buffer_copy(data)
        body_data = data[4:]

        # These bytes should always be zero
        if list(hdr.reserved) != [0]*3:
            self.bad_packet = True
            return

        if hdr.type == 1:
            body = wg_initiate.from_buffer_copy(body_data)
            self.handle_initiate(hdr, body, body_data)

        elif hdr.type == 2:
            body = wg_respond.from_buffer_copy(body_data)
            self.handle_respond(hdr, body, body_data)

        elif hdr.type == 3:
            body = wg_cookie.from_buffer_copy(body_data)

        elif hdr.type == 4:
            body = wg_transport.from_buffer_copy(body_data)
            self.handle_transport(hdr, body)

        else:
            self.bad_packet = True
            return

        
        return hdr, body


    def is_datachannel_packet(self, packet):
        hdr, body = self.process_packet(packet)
        return hdr.type == 4


    def handle_initiate(self, hdr, body, data):
        if len(data) != sizeof(wg_initiate):
            self.bad_packet = True
            return
        
        # It's exactly the size of wg_initiate and doesn't have a bad header
        self.points += 10
        if list(body.mac2) == [0]*16:
            self.points += 10
        
        self.sources.add(tuple(body.sender))


    def handle_respond(self, hdr, body, data):
        if len(data) != sizeof(wg_respond):
            self.bad_packet = True
            return

        # It's exactly the size of wg_respond
        self.points += 10

        # If we've seen the initiate packet and it matches
        self.destinations.add(tuple(body.receiver))
        if tuple(body.receiver) in self.sources:
            self.points += 10

        self.sources.add(tuple(body.sender))

        # It's likely that mac2 is zero, and it's probably not common to see this in other protocols
        if list(body.mac2) == [0]*16:
            self.points += 10


    def handle_transport(self, hdr, body: wg_transport):
        if tuple(body.receiver) in self.sources or tuple(body.receiver) in self.destinations:
            self.points += 10
        else:
            self.destinations.add(tuple(body.receiver))

        # This is a little endian counter
        # This conditional is true as long as they haven't sent 2^40 packets over the VPN
        if body.counter[5:] == [0]*3:
            self.points += 5

        # This would require them to send 2^56 packets
        if body.counter[7]:
            self.bad_packet = True
            return

        # Check if the counter matches
        receiver = int.from_bytes(body.receiver, 'little')
        counter  = int.from_bytes(body.counter, 'little')
        if receiver in self.dest_ctrs:
            if self.dest_ctrs[receiver] + 1 == counter:
                self.points += 10


        self.dest_ctrs[receiver] = counter


class LightwayDetector(Detector):
    """
    Detects the Lightway VPN protocol in ~3 packets. Minimum is 3 packets
    """

    def __init__(self):
        self.bad_packet = False
        self.points     = 0
        self.threshold  = 50

        self.session_ids = set()

    @property
    def can_filter_datachannel(self):
        return False


    def process_packet(self, data):
        header = he_wire_hdr.from_buffer_copy(data)

        # Correctness check
        if header.he != b'He' or bytes(header.reserved) != b'\x00\00\x00':
            self.bad_packet = True
            return

        # Current major version is 1; futureproof by allowing 2
        if header.major_version > 2:
            self.bad_packet = True

        self.points += 10

        if header.session in self.session_ids:
            self.points += 10
        else:
            self.session_ids.add(header.session)

