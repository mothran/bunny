import struct, os

import pylorcon
from pcapy import open_live

from config import *

class SendRec:
	"""
	
	Main IO functionality of bunny, using pcapy and lorcon to do send and receive.
	
	"""
	def __init__(self):		
		try:
			self.lorcon = pylorcon.Lorcon(IFACE, DRIVER)
		except pylorcon.LorconError as err:
			print "Error creating lorcon object: "
			print str(err)
			exit()
		
		# check for monitor mode, if not already in monitor mode, make it.
		if (self.lorcon.getmode() != "MONITOR"):
			os.system("ifconfig " + IFACE + " down");
			self.lorcon.setmode("MONITOR");
			os.system("ifconfig " + IFACE + " up");
		
		self.lorcon.setfunctionalmode("INJECT");
		self.lorcon.setchannel(CHANNEL);
		
		# Quick definitions for pcapy
		MAX_LEN      = 1514		# max size of packet to capture
		PROMISCUOUS  = 1		# promiscuous mode?
		READ_TIMEOUT = 0		# in milliseconds
		MAX_PKTS     = 1		# number of packets to capture; 0 => no limit
		try:
			self.pcapy = open_live(IFACE, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
		except:
			print "Error creating pcapy descriptor, try turning on the target interface or setting it to monitor mode"
	
	def updateChan(self, channel):
		"""
		
		Updates the current channel
		
		"""
		self.lorcon.setchannel(channel)
	
	# These send/rec functions should be used in hidden / paranoid mode.
	def sendPacket(self, data):
		if data is not None:
			self.lorcon.txpacket(data)
	def recPacket(self):
		# return the raw packet if the mod/remain value is correct. 
		run = True 
		while(run):
			header, rawPack = self.pcapy.next()
			size = len(rawPack)			
			if (round( size % MODULUS, 2) == REMAINDER):
				run = False
				# H = unsigned short
				size = struct.unpack("<H", rawPack[2:4])
				size = int(size[0])				
				rawPack = rawPack[size:]
				return rawPack
	
	# these functions should be used if you dont care about being noticed
	def sendPacketDurFix(self, data):
		data = "\x00\x00\x00\x00" + data
		
		# Create a packet with proper length, add radiotap header length + zeros.
		while( round((len(data) + RADIOTAPLEN) % MODULUS, 2) != remainder):
			data = data + os.urandom(1);
		self.lorcon.txpacket(data)
	def recPacketDurFix(self):
		# return the raw packet if the mod/remain value is correct. 
		run = True 
		while(run):
			header, rawPack = self.pcapy.next()
			size = len(rawPack)
			if (round(size % MODULUS, 2) == remainder):
				run = False
				# H = unsigned short
				sizeHead = struct.unpack("<H", rawPack[2:4])
				
				# the + 4 is for the 4 null bytes that pad the durration field
				sizeHead = int(sizeHead[0]) + 4
				rawPack = rawPack[sizeHead:]
				return rawPack
	
	def reloop(self):
		"""
		This exists only for testing purposes.
		Too ensure proper packets are read properly and at a high enough rate. 
		"""
		count = 0
		packNum = 2000
		startTime = time.time()
		for n in range(packNum):
			header, rawPack = self.pcapy.next()
			size = len(rawPack)
			if (size % MODULUS == remainder):
				print "pack num: %d, length is divisible by 4" % n  
		endTime = time.time()
		totalTime = endTime - startTime
		packPerSec = packNum / totalTime
		print "Total Packets (p/s): %s" % packPerSec

	def recvRaw(self):
		""" Returns packet	
		
		RadioTap headers included
		
		"""
		header, rawPack = self.pcapy.next()
		return rawPack
