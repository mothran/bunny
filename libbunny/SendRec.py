import struct, os, time

import pylorcon
from pcapy import open_live

from config import *

class TimeoutWarning():
	"""
	
	Homebrew Exception class for packet reading timeouts
	The timeout config global varible is related to when this class is used.
	
	"""
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return self.value


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
			os.system("ifconfig " + IFACE + " down")
			self.lorcon.setmode("MONITOR")
			os.system("ifconfig " + IFACE + " up")
			
			#This sleep exists to wait for the changes of mode to be pushed to the interface
			time.sleep(1)
		
		self.lorcon.setfunctionalmode("INJECT")
		self.lorcon.setchannel(CHANNEL)
		
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
		while(True):
			header, rawPack = self.pcapy.next()
			size = len(rawPack)
			if (round( size % MODULUS, 2) == REMAINDER):
				# H = unsigned short
				size = struct.unpack("<H", rawPack[2:4])
				size = int(size[0])
				rawPack = rawPack[size:]
				return rawPack
	def recPacket_timeout(self, fcs):
		# return the raw packet if the mod/remain value is correct. 
		start_t = time.time()
		while(time.time() - start_t < TIMEOUT):
			header, rawPack = self.pcapy.next()
			# H = unsigned short
			size = struct.unpack("<H", rawPack[2:4])
			size = int(size[0])
			
			# check if the radio tap header is from the interface face itself (loop backs)
			#  that '18' might need to change with different hardware and software drivers
			if size >= 18:
				rawPack = rawPack[size:]
				size = len(rawPack)
				# subtract the FCS to account for the radiotap header adding a CRC32
				if (round( (size - fcs) % MODULUS, 2) == REMAINDER):
					return rawPack
		else:
			raise TimeoutWarning("timedout")
	
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
			if (size % MODULUS == REMAINDER):
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
