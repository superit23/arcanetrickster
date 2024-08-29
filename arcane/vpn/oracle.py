from arcane.vpn.packet import wg_hdr, wg_initiate, wg_respond, wg_cookie, wg_transport, he_wire_hdr
from arcane.core.serialization import Serializable
from ctypes import sizeof
import time


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
        self.bad_packet  = False
        self.points      = 0
        self.threshold   = 50

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



S1 = Serializable[1]
class OpenVPNUDPPacket(S1):
    op_and_key: S1.UInt8
    session_id: S1.UInt64
    hmac: S1.Bytes[20]
    replay_packet_id: S1.UInt32


class OpenVPNControlPacket(S1):
    net_time: S1.UInt32
    acked_packets: S1.SizedList[S1.UInt32]
    remote_session_id: S1.UInt64
    message_packet_id: S1.UInt32
    payload: S1.GreedyBytes


class OpenVPNAckPacket(S1):
    net_time: S1.UInt32
    acked_packets: S1.SizedList[S1.UInt32]
    remote_session_id: S1.UInt64


class OpenVPNDataV1Packet(S1):
    op_and_key: S1.UInt8
    payload: S1.GreedyBytes


class OpenVPNDataV2Packet(S1):
    op_and_key: S1.UInt8
    peer_id: S1.Bytes[3]
    payload: S1.GreedyBytes


class OpenVPNDetector(Detector):
    """
    Detects the OpenVPN VPN protocol in ~1-3 packets.
    https://github.com/corelight/zeek-spicy-openvpn/blob/master/analyzer/analyzer.spicy
    """

    def __init__(self):
        self.bad_packet = False
        self.points     = 0
        self.threshold  = 50
        self.session_id_pairs = set()
        self.replay_counters  = {}
        self.hmac_uni_ctr     = []
        self.hmac_strikes     = 0
    

    def analyze_hmac_distribution(self, hmac: bytes):
        """
        Due to the relatively low number of failure cases, this methods attempts to analyze the HMAC bit distribution.
        The idea is to detect a poor distribution before a false positive can occur while minimizing the chance of a false negative.
        The rest of the detector is likely to detect a true positive before a false negative could occur.
        """
        hmac_bin = bin(int.from_bytes(hmac, 'big'))[2:].zfill(160)
        uni_diff = abs(80-hmac_bin.count('1'))

        # Use the last 5 samples
        self.hmac_uni_ctr.append(uni_diff // 3)
        self.hmac_uni_ctr = self.hmac_uni_ctr[:5]

        # ~0.6% for a uniform distribution
        if sum(self.hmac_uni_ctr) > 17:
            self.hmac_strikes += 1
            self.points        = 0
            self.hmac_uni_ctr  = []

        # ~5.5% for a uniform distribution
        elif sum(self.hmac_uni_ctr) > 13:
            self.hmac_strikes += 0.5
            self.hmac_uni_ctr  = []


        elif len(self.hmac_uni_ctr) == 5:
            # ~26% for a uniform distribution
            if sum(self.hmac_uni_ctr) < 7:
                self.hmac_strikes = max(self.hmac_strikes-1, 0)
            
            self.hmac_uni_ctr = []



    def process_packet(self, data):
        packet = OpenVPNUDP.deserialize(data)[1]
        op, key_id = divmod(int(packet.op_and_key), 8) 

        # Likely to have low value key IDs
        if key_id == 0:
            self.points += 5
        elif key_id < 3:
            self.points += 2

        # Correctness check; these are the only allowed values
        if not op in range(3, 12):
            print("Bad op")
            self.bad_packet = True
            return
        
        self.analyze_hmac_distribution(bytes(packet.hmac))

        if self.hmac_strikes > 2:
            print("HMAC")
            self.bad_packet = True
            return

        self.points += 5

        curr_time = int(time.time())

        # Check whether the net time value is close to current time
        if int(packet.net_time) in range(curr_time-300, curr_time+300):
            self.points += 10
        

        # It's possible that we'll get captures from the past. However, we should never see data from the future
        if int(packet.net_time) - curr_time > 86400:
            print("TIME")
            self.bad_packet = True
            return
        

        # Replay packet ID is likely to be low
        if not (int(packet.replay_packet_id) >> 24):
            self.points += 2

        if not (int(packet.replay_packet_id) >> 16):
            self.points += 3

        # Message packet ID is likely to be low
        if not (int(packet.message_packet_id) >> 24):
            self.points += 2

        if not (int(packet.message_packet_id) >> 16):
            self.points += 3


        # Check if ACKs are numerically close; unlikely for non-related packets
        if len(packet.acked_packets) > 1:
            sorted_acks = sorted([int(pid) for pid in packet.acked_packets])
            if (sorted_acks[1] - sorted_acks[0]) < len(sorted_acks)*2:
                self.points += 5*len(sorted_acks)


        # Match on session IDs
        if (int(packet.session_id), int(packet.remote_session_id)) in self.session_id_pairs:
            self.points += 10
        else:
            self.session_id_pairs.add((int(packet.session_id), int(packet.remote_session_id)))


        # Check if replay counter continues from previous
        if int(packet.session_id) in self.replay_counters:
            if int(packet.replay_packet_id) == self.replay_counters[int(packet.session_id)] + 1:
                self.points += 10
        
        self.replay_counters[int(packet.session_id)] = int(packet.replay_packet_id)

