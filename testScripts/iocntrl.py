import socket
import os
import array
import fcntl
import struct

ifname = "wlan0"
IFNAMSIZE = 16
data = ""
SIOCGIWNAME      = 0x8B01
SIOCGIWSTATS     = 0x8B0F
SIOCGIWESSID     = 0x8B1B
request = SIOCGIWSTATS

sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

buff = IFNAMSIZE-len(ifname)
args = array.array('c', ifname + '\0'*buff)

packed = "\x00"*32
packed = array.array("c", packed)
caddr_t, length = packed.buffer_info()
data = struct.pack("PHH", caddr_t, length, 0)

if data is not None:
	args.extend(data)
else:
	buff = 32
	args.extend('\0'*buff)

result = fcntl.ioctl(sockfd.fileno(), request, args)
print packed
