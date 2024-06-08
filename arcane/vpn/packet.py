import ctypes

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
