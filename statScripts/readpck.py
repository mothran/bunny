import binascii
import struct
import time
import sys

from pcapy import open_live

if len(sys.argv) > 1:
	IFACE = sys.argv[1]
else:
	print "USAGE: python readpck.py IFACE"

MAX_LEN      = 1514		# max size of packet to capture
PROMISCUOUS  = 1		# promiscuous mode?
READ_TIMEOUT = 1000		# in milliseconds
MAX_PKTS     = 1		# number of packets to capture; 0 => no limit
try:
	pcapy = open_live(IFACE, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
except:
	print "Error creating pcapy descriptor, try turning on the target interface or setting it to monitor mode"

cnt = 0

start_t = time.time()
while(time.time() - start_t < 5):
	header, rawPack = pcapy.next()
	# H = unsigned short
	size = struct.unpack("<H", rawPack[2:4])
	size = int(size[0])
	
	# check if the radio tap header is from the interface face itself (loop backs)
	#  that '18' might need to change with different hardware and software drivers
	if size >= 18:
		rawPack = rawPack[size:]
		size = len(rawPack)
		# subtract the FCS to account for the radiotap header adding a CRC32
		if (round( (size - 4) % 1.21, 2) == 0.85):
			#print "got packet"
			cnt = cnt + 1
			#print binascii.hexlify(rawPack) + "\n"

print cnt
