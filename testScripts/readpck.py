import binascii
import struct

from pcapy import open_live

IFACE = "wlan2"
MAX_LEN      = 1514		# max size of packet to capture
PROMISCUOUS  = 1		# promiscuous mode?
READ_TIMEOUT = 0		# in milliseconds
MAX_PKTS     = 1		# number of packets to capture; 0 => no limit
try:
	pcapy = open_live(IFACE, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
except:
	print "Error creating pcapy descriptor, try turning on the target interface or setting it to monitor mode"


while(True):
	header, rawPack = pcapy.next()

	# get radiotap and strip
	size = struct.unpack("<H", rawPack[2:4])
	size = int(size[0])
	print size
	rawPack = rawPack[size:]
	size = len(rawPack)
	#print size
	#print binascii.hexlify(rawPack[0:1])
	if (round(size % 1.21, 2) == 0.85):
		print "\tgot bunny"
	
