import ctypes
import fcntl
from enum import IntFlag

# https://android.googlesource.com/platform/external/kernel-headers/+/ics-aah-release/original/linux/if_tun.h
# https://www.kernel.org/doc/Documentation/networking/tuntap.txt
# https://stackoverflow.com/questions/6067405/python-sockets-enabling-promiscuous-mode-in-linux
# https://jvns.ca/blog/2022/09/06/send-network-packets-python-tun-tap/
# https://github.com/torvalds/linux/blob/master/include/uapi/linux/wireless.h

class KernelFlags(IntFlag):
    LINUX_IFF_TUN   = 0x0001 # TUN type
    LINUX_IFF_TAP   = 0x0002 # TAP type
    LINUX_IFF_NO_PI = 0x1000
    LINUX_TUNSETIFF = 0x400454CA # Set IFF
    IFF_PROMISC     = 0x100 # Promiscious flag
    SIOCGIFFLAGS    = 0x8913 # Get IFF flags
    SIOCSIFFLAGS    = 0x8914 # Set IFF flags
    SIOCSIWMODE     = 0x8B06 # Set monitor mode
    SIOCGIWMODE     = 0x8B07 # Get monitor mode


# Ripped straight out of the kernel (🙏)
# https://github.com/torvalds/linux/blob/master/include/uapi/linux/wireless.h
class WirelessFlags(IntFlag):
    SIOCSIWCOMMIT = 0x8B00 # /* Commit pending changes to driver */
    SIOCGIWNAME   = 0x8B01 # /* get name == wireless protocol */

# /* SIOCGIWNAME is used to verify the presence of Wireless Extensions.
#  * Common values : "IEEE 802.11-DS", "IEEE 802.11-FH", "IEEE 802.11b"...
#  * Don't put the name of your driver there, it's useless. */

# /* Basic operations */
    SIOCSIWNWID = 0x8B02 # /* set network id (pre-802.11) */
    SIOCGIWNWID = 0x8B03 # /* get network id (the cell) */
    SIOCSIWFREQ = 0x8B04 # /* set channel/frequency (Hz) */
    SIOCGIWFREQ = 0x8B05 # /* get channel/frequency (Hz) */
    SIOCSIWMODE = 0x8B06 # /* set operation mode */
    SIOCGIWMODE = 0x8B07 # /* get operation mode */
    SIOCSIWSENS = 0x8B08 # /* set sensitivity (dBm) */
    SIOCGIWSENS = 0x8B09 # /* get sensitivity (dBm) */

# /* Informative stuff */
    SIOCSIWRANGE = 0x8B0A # /* Unused */
    SIOCGIWRANGE = 0x8B0B # /* Get range of parameters */
    SIOCSIWPRIV  = 0x8B0C # /* Unused */
    SIOCGIWPRIV  = 0x8B0D # /* get private ioctl interface info */
    SIOCSIWSTATS = 0x8B0E # /* Unused */
    SIOCGIWSTATS = 0x8B0F # /* Get /proc/net/wireless stats */
# /* SIOCGIWSTATS is strictly used between user space and the kernel, and
#  * is never passed to the driver (i.e. the driver will never see it). */

# /* Spy support (statistics per MAC address - used for Mobile IP support) */
    SIOCSIWSPY    = 0x8B10 # /* set spy addresses */
    SIOCGIWSPY    = 0x8B11 # /* get spy info (quality of link) */
    SIOCSIWTHRSPY = 0x8B12 # /* set spy threshold (spy event) */
    SIOCGIWTHRSPY = 0x8B13 # /* get spy threshold */

# /* Access Point manipulation */
    SIOCSIWAP     = 0x8B14 # /* set access point MAC addresses */
    SIOCGIWAP     = 0x8B15 # /* get access point MAC addresses */
    SIOCGIWAPLIST = 0x8B17 # /* Deprecated in favor of scanning */
    SIOCSIWSCAN   = 0x8B18 # /* trigger scanning (list cells) */
    SIOCGIWSCAN   = 0x8B19 # /* get scanning results */

# /* 802.11 specific support */
    SIOCSIWESSID = 0x8B1A # /* set ESSID (network name) */
    SIOCGIWESSID = 0x8B1B # /* get ESSID */
    SIOCSIWNICKN = 0x8B1C # /* set node name/nickname */
    SIOCGIWNICKN = 0x8B1D # /* get node name/nickname */
# /* As the ESSID and NICKN are strings up to 32 bytes long, it doesn't fit
#  * within the 'iwreq' structure, so we need to use the 'data' member to
#  * point to a string in user space, like it is done for RANGE... */

# /* Other parameters useful in 802.11 and some other devices */
    SIOCSIWRATE  = 0x8B20 # /* set default bit rate (bps) */
    SIOCGIWRATE  = 0x8B21 # /* get default bit rate (bps) */
    SIOCSIWRTS   = 0x8B22 # /* set RTS/CTS threshold (bytes) */
    SIOCGIWRTS   = 0x8B23 # /* get RTS/CTS threshold (bytes) */
    SIOCSIWFRAG  = 0x8B24 # /* set fragmentation thr (bytes) */
    SIOCGIWFRAG  = 0x8B25 # /* get fragmentation thr (bytes) */
    SIOCSIWTXPOW = 0x8B26 # /* set transmit power (dBm) */
    SIOCGIWTXPOW = 0x8B27 # /* get transmit power (dBm) */
    SIOCSIWRETRY = 0x8B28 # /* set retry limits and lifetime */
    SIOCGIWRETRY = 0x8B29 # /* get retry limits and lifetime */

# /* Encoding stuff (scrambling, hardware security, WEP...) */
    SIOCSIWENCODE = 0x8B2A # /* set encoding token & mode */
    SIOCGIWENCODE = 0x8B2B # /* get encoding token & mode */
# /* Power saving stuff (power management, unicast and multicast) */
    SIOCSIWPOWER  = 0x8B2C # /* set Power Management settings */
    SIOCGIWPOWER  = 0x8B2D # /* get Power Management settings */

# /* WPA : Generic IEEE 802.11 informatiom element (e.g., for WPA/RSN/WMM).
#  * This ioctl uses struct iw_point and data buffer that includes IE id and len
#  * fields. More than one IE may be included in the request. Setting the generic
#  * IE to empty buffer (len=0) removes the generic IE from the driver. Drivers
#  * are allowed to generate their own WPA/RSN IEs, but in these cases, drivers
#  * are required to report the used IE as a wireless event, e.g., when
#  * associating with an AP. */
    SIOCSIWGENIE = 0x8B30 # /* set generic IE */
    SIOCGIWGENIE = 0x8B31 # /* get generic IE */

# /* WPA : IEEE 802.11 MLME requests */
    SIOCSIWMLME = 0x8B16 # /* request MLME operation; uses struct iw_mlme */
# /* WPA : Authentication mode parameters */
    SIOCSIWAUTH = 0x8B32 # /* set authentication mode params */
    SIOCGIWAUTH = 0x8B33 # /* get authentication mode params */

# /* WPA : Extended version of encoding configuration */
    SIOCSIWENCODEEXT = 0x8B34 # /* set encoding token & mode */
    SIOCGIWENCODEEXT = 0x8B35 # /* get encoding token & mode */

# /* WPA2 : PMKSA cache management */
    SIOCSIWPMKSA = 0x8B36 # /* PMKSA cache operation */


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
