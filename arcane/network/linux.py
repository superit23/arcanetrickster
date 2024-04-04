import ctypes
import fcntl
from enum import IntFlag

# https://android.googlesource.com/platform/external/kernel-headers/+/ics-aah-release/original/linux/if_tun.h
# https://www.kernel.org/doc/Documentation/networking/tuntap.txt
# https://stackoverflow.com/questions/6067405/python-sockets-enabling-promiscuous-mode-in-linux
# https://jvns.ca/blog/2022/09/06/send-network-packets-python-tun-tap/

class KernelFlags(IntFlag):
    LINUX_IFF_TUN   = 0x0001
    LINUX_IFF_TAP   = 0x0002
    LINUX_IFF_NO_PI = 0x1000
    LINUX_TUNSETIFF = 0x400454CA
    IFF_PROMISC     = 0x100
    SIOCGIFFLAGS    = 0x8913
    SIOCSIFFLAGS    = 0x8914


class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]


class KernelInterface(object):
    def get_current(self):
        ifr = ifreq()
        ifr.ifr_ifrn = self.name.encode('utf-8')
        fcntl.ioctl(self.fd, KernelFlags.SIOCGIFFLAGS.value, ifr)

        return ifr


    def set_promiscious(self):
        ifr = self.get_current()
        ifr.ifr_flags |= KernelFlags.IFF_PROMISC.value
        fcntl.ioctl(self.fd, KernelFlags.SIOCSIFFLAGS.value, ifr)


    def set_tap(self):
        ifr = ifreq()
        ifr.ifr_ifrn = self.name.encode('utf-8')
        ifr.ifr_flags |= int(KernelFlags.LINUX_IFF_TAP | KernelFlags.LINUX_IFF_NO_PI)
        fcntl.ioctl(self.fd, KernelFlags.LINUX_TUNSETIFF.value, ifr)
