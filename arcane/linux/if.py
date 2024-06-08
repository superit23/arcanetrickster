import ctypes
import fcntl
from enum import IntFlag

class InterfaceFlags(IntFlag):
    LINUX_IFF_TUN   = 0x0001 # TUN type
    LINUX_IFF_TAP   = 0x0002 # TAP type
    LINUX_IFF_NO_PI = 0x1000
    LINUX_TUNSETIFF = 0x400454CA # Set IFF
    IFF_PROMISC     = 0x100 # Promiscious flag
    SIOCGIFFLAGS    = 0x8913 # Get IFF flags
    SIOCSIFFLAGS    = 0x8914 # Set IFF flags

class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]
