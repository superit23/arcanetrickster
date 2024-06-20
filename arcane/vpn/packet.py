# from arcane.core.serialization import *
from enum import IntFlag
import ctypes


############
# LIGHTWAY #
############

# https://github.com/expressvpn/lightway-core/blob/c0c7cf2b5fbb101e7b48565d238d3dd81a7d0675/include/he.h#L574
# classtypedef struct he_wire_hdr {
#   // First two bytes to contain the 'H' and 'e'
#   char he[2];
#   // Version of the wire protocol
#   uint8_t major_version;
#   uint8_t minor_version;
#   // Request aggressive mode
#   uint8_t aggressive_mode;
#   // Three bytes reserved for future use
#   uint8_t reserved[3];
#   // 64 bit session identifier
#   uint64_t session;
# } he_wire_hdr_t;

class he_wire_hdr(ctypes.Structure):
    _fields_ = [("he", ctypes.c_char * 2),
                ("major_version", ctypes.c_uint8),
                ("minor_version", ctypes.c_uint8),
                ("aggressive_mode", ctypes.c_uint8),
                ("reserved", ctypes.c_uint8 * 3),
                ("session", ctypes.c_uint64)]



#############
# WIREGUARD #
#############

# https://www.wireguard.com/papers/wireguard.pdf
class wg_hdr(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint8),
                ("reserved", ctypes.c_uint8 * 3)]


# 0x1
class wg_initiate(ctypes.Structure):
    _fields_ = [("sender", ctypes.c_uint8 * 4),
                ("ephemeral", ctypes.c_uint8 * 32),
                ("static", ctypes.c_uint8 * (32+16)),
                ("timestamp", ctypes.c_uint8 * (12+16)),
                ("mac1", ctypes.c_uint8 * 16),
                ("mac2", ctypes.c_uint8 * 16)]

# 0x2
class wg_respond(ctypes.Structure):
    _fields_ = [("sender", ctypes.c_uint8 * 4),
                ("receiver", ctypes.c_uint8 * 4),
                ("ephemeral", ctypes.c_uint8 * 32),
                ("empty", ctypes.c_uint8 * (0+16)),
                ("mac1", ctypes.c_uint8 * 16),
                ("mac2", ctypes.c_uint8 * 16)]


# 0x3
class wg_cookie(ctypes.Structure):
    _fields_ = [("receiver", ctypes.c_uint8 * 4),
                ("nonce", ctypes.c_uint8 * 24),
                ("cookie", ctypes.c_uint8 * 32)]


# 0x4
class wg_transport(ctypes.Structure):
    _fields_ = [("receiver", ctypes.c_uint8 * 4),
                ("counter", ctypes.c_uint8 * 8)]



###########
# OPENVPN #
###########


# https://github.com/OpenVPN/openvpn/blob/13ee7f902f18e27b981f8e440facd2e6515c6c83/src/openvpn/ssl_pkt.h#L48

# #define P_CONTROL_HARD_RESET_CLIENT_V1 1     /* initial key from client, forget previous state */
# #define P_CONTROL_HARD_RESET_SERVER_V1 2     /* initial key from server, forget previous state */
# #define P_CONTROL_SOFT_RESET_V1        3     /* new key, graceful transition from old to new key */
# #define P_CONTROL_V1                   4     /* control channel packet (usually TLS ciphertext) */
# #define P_ACK_V1                       5     /* acknowledgement for packets received */
# #define P_DATA_V1                      6     /* data channel packet */
# #define P_DATA_V2                      9     /* data channel packet with peer-id */

# /* indicates key_method >= 2 */
# #define P_CONTROL_HARD_RESET_CLIENT_V2 7     /* initial key from client, forget previous state */
# #define P_CONTROL_HARD_RESET_SERVER_V2 8     /* initial key from server, forget previous state */

# /* indicates key_method >= 2 and client-specific tls-crypt key */
# #define P_CONTROL_HARD_RESET_CLIENT_V3 10    /* initial key from client, forget previous state */

# /* Variant of P_CONTROL_V1 but with appended wrapped key
#  * like P_CONTROL_HARD_RESET_CLIENT_V3 */
# #define P_CONTROL_WKC_V1               11


class OpenVPNPacketType(IntFlag):
    P_CONTROL_HARD_RESET_CLIENT_V1 = 1
    P_CONTROL_HARD_RESET_SERVER_V1 = 2
    P_CONTROL_SOFT_RESET_V1        = 3
    P_CONTROL_V1                   = 4
    P_ACK_V1                       = 5
    P_DATA_V1                      = 6
    P_DATA_V2                      = 9
    P_CONTROL_HARD_RESET_CLIENT_V2 = 7
    P_CONTROL_HARD_RESET_SERVER_V2 = 8
    P_CONTROL_HARD_RESET_CLIENT_V3 = 10
    P_CONTROL_WKC_V1               = 11


# https://github.com/corelight/zeek-spicy-openvpn/blob/master/analyzer/analyzer.spicy
# https://github.com/OpenVPN/openvpn-rfc/blob/master/openvpn-wire-protocol.xml

# public type ControlMessage = unit(opcode: Opcode, key_id: uint8, hmac_size: uint32) {
# 	var opcode: Opcode = opcode;
# 	var key_id: uint8 = key_id;
# 	session_id: bytes &size=8;
# 	hmac: HMACInfo(hmac_size) if (hmac_size > 0);
# 	packet_id_array_len: uint8;
# 	packet_id_array: uint32[self.packet_id_array_len];
# 	remote_session_id: bytes &size=8 if (self.packet_id_array_len > 0);
# 	packet_id: uint32;
# 	ssl_data: bytes &eod;
# };


# struct control_packet {
#     int opcode:5;
#     int keyid:3;
#     uint64_t own_session_id;
#     uint8_t acked_pktid_len;
#     uint8_t[n*8] acked_pktid_list; [only if acked_id_len > 0]
#     uint64_t peer_session_id; [only if acked_id_len > 0]
#     uint32_t packet_id;
#     uint8_t control_channel_payload[];
# }

class ovpn_control_message_0(ctypes.Structure):
    _fields_ = [("op_and_key_id", ctypes.c_uint8),
                ("session_id", ctypes.c_uint8 * 8),
                ("acked_pktid_len", ctypes.c_uint8)]
                # ("acked_pktid_list", ctypes.c_uint8 * 256),
                # ("remote_session_id", ctypes.c_uint64),
                # ("packet_id", ctypes.c_uint32)]

class ovpn_control_message_1(ctypes.Structure):
    _fields_ = [("remote_session_id", ctypes.c_uint8 * 8),
                ("packet_id", ctypes.c_uint8 * 4)]
    

# type AckMessage = unit(opcode: Opcode, key_id: uint8, hmac_size: uint32) {
# 	var opcode: Opcode = opcode;
# 	var key_id: uint8 = key_id;
# 	session_id: bytes &size=8;
# 	hmac: HMACInfo(hmac_size) if (hmac_size > 0);
# 	packet_id_array_len : uint8;
# 	packet_id_array: uint32[self.packet_id_array_len];
# 	remote_session_id: bytes &size=8;
# };

class ovpn_ack_message(ctypes.Structure):
    _fields_ = [("op_and_key_id", ctypes.c_uint8),
                ("session_id", ctypes.c_uint8),
                ("hmac", ctypes.c_uint8 * 32),
                ("op_and_key_id", ctypes.c_uint8),
                ("op_and_key_id", ctypes.c_uint8),
                ("op_and_key_id", ctypes.c_uint8),
                ("op_and_key_id", ctypes.c_uint8),]


# type DataMessage = unit(opcode: Opcode, key_id: uint8, is_v2: bool) {
# 	var opcode: Opcode = opcode;
# 	var key_id: uint8 = key_id;
# 	peer_id: bytes &size=3 if (is_v2);
# 	payload: bytes &eod;
# };

# OpenVPN notes
# Session ID is per host per connection
# Remote session ID is the other host's session
# Replay-Packet-ID starts at 1
# Message-Packet-ID starts at 0
# Both replay and message IDs increment per host
# Time is included
