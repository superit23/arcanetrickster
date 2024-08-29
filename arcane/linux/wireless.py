from enum import IntFlag
import ctypes


IFNAMSIZ = 16


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


    def get_method_name(self):
        action, attr = self.name.split("IW")
        if action == "SIOCG":
            name = "get"
        else:
            name = "set"

        return f'{name}_iw_{attr.lower()}'



class iw_param(ctypes.Structure):
    _fields_ = [("value", ctypes.c_int32),
                ("fixed", ctypes.c_uint8),
                ("disabled", ctypes.c_uint8),
                ("flags", ctypes.c_uint16)]


# struct iw_point {
#   void __user	*pointer;	/* Pointer to the data  (in user space) */
#   __u16		length;		/* number of fields or size in bytes */
#   __u16		flags;		/* Optional params */
# };


class iw_point(ctypes.Structure):
    _fields_ = [("pointer", ctypes.c_void_p),
                ("length", ctypes.c_uint16),
                ("flags", ctypes.c_uint16)]


# /*
#  *	A frequency
#  *	For numbers lower than 10^9, we encode the number in 'm' and
#  *	set 'e' to 0
#  *	For number greater than 10^9, we divide it by the lowest power
#  *	of 10 to get 'm' lower than 10^9, with 'm'= f / (10^'e')...
#  *	The power of 10 is in 'e', the result of the division is in 'm'.
#  */
# struct iw_freq {
# 	__s32		m;		/* Mantissa */
# 	__s16		e;		/* Exponent */
# 	__u8		i;		/* List index (when in range struct) */
# 	__u8		flags;		/* Flags (fixed/auto) */
# };

class iw_freq(ctypes.Structure):
    _fields_ = [("m", ctypes.c_int32),
                ("e", ctypes.c_int16),
                ("i", ctypes.c_int8),
                ("flags", ctypes.c_int8)]

# /*
#  *	Quality of the link
#  */
# struct iw_quality {
# 	__u8		qual;		/* link quality (%retries, SNR,
# 					   %missed beacons or better...) */
# 	__u8		level;		/* signal level (dBm) */
# 	__u8		noise;		/* noise level (dBm) */
# 	__u8		updated;	/* Flags to know if updated */
# };

class iw_quality(ctypes.Structure):
    _fields_ = [("qual", ctypes.c_uint8),
                ("level", ctypes.c_uint8),
                ("noise", ctypes.c_uint8),
                ("updated", ctypes.c_uint8)]


# struct sockaddr {
# 	sa_family_t	sa_family;	/* address family, AF_xxx	*/
# 	union {
# 		char sa_data_min[14];		/* Minimum 14 bytes of protocol address	*/
# 		DECLARE_FLEX_ARRAY(char, sa_data);
# 	};
# };


class sockaddr(ctypes.Union):
    _fields_ = [("sa_family", ctypes.c_uint16),
                ("sa_data_min", ctypes.c_char * 14),
                ("sa_data", ctypes.c_uint8)]


# union iwreq_data {
# 	/* Config - generic */
# 	char		name[IFNAMSIZ];
# 	/* Name : used to verify the presence of  wireless extensions.
# 	 * Name of the protocol/provider... */

# 	struct iw_point	essid;		/* Extended network name */
# 	struct iw_param	nwid;		/* network id (or domain - the cell) */
# 	struct iw_freq	freq;		/* frequency or channel :
# 					 * 0-1000 = channel
# 					 * > 1000 = frequency in Hz */

# 	struct iw_param	sens;		/* signal level threshold */
# 	struct iw_param	bitrate;	/* default bit rate */
# 	struct iw_param	txpower;	/* default transmit power */
# 	struct iw_param	rts;		/* RTS threshold */
# 	struct iw_param	frag;		/* Fragmentation threshold */
# 	__u32		mode;		/* Operation mode */
# 	struct iw_param	retry;		/* Retry limits & lifetime */

# 	struct iw_point	encoding;	/* Encoding stuff : tokens */
# 	struct iw_param	power;		/* PM duration/timeout */
# 	struct iw_quality qual;		/* Quality part of statistics */

# 	struct sockaddr	ap_addr;	/* Access point address */
# 	struct sockaddr	addr;		/* Destination address (hw/mac) */

# 	struct iw_param	param;		/* Other small parameters */
# 	struct iw_point	data;		/* Other large parameters */
# };


class tester(ctypes.Structure):
  _fields_ = [("name", ctypes.c_char * IFNAMSIZ),
              ("mode", ctypes.c_uint32)]

class iwreq_data(ctypes.Union):
    _fields_ = [("name", ctypes.c_char * IFNAMSIZ),
                ("essid", iw_point),
                ("nwid", iw_param),
                ("freq", iw_freq),
                ("sens", iw_param),
                ("bitrate", iw_param),
                ("txpower", iw_param),
                ("rts", iw_param),
                ("frag", iw_param),
                ("mode", ctypes.c_uint32),
                ("retry", iw_param),
                ("encoding", iw_point),
                ("power", iw_param),
                ("qual", iw_quality),
                ("ap_addr", sockaddr),
                ("addr", sockaddr),
                ("param", iw_param),
                ("data", iw_point)]


# /*
#  * The structure to exchange data for ioctl.
#  * This structure is the same as 'struct ifreq', but (re)defined for
#  * convenience...
#  * Do I need to remind you about structure size (32 octets) ?
#  */
# struct iwreq {
# 	union
# 	{
# 		char	ifrn_name[IFNAMSIZ];	/* if name, e.g. "eth0" */
# 	} ifr_ifrn;

# 	/* Data part (defined just above) */
# 	union iwreq_data	u;
# };



class ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_addr", ctypes.c_char * 14)]
