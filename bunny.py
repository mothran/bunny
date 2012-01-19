#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       bunny.py
#       
#       Copyright 2011 Mothra <mothra@rouges>
#       
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#       
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#       
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#       MA 02110-1301, USA.
#       
#     

# system imports:  
import sys, os, time, struct, operator, random

# depends:
import pylorcon
from Crypto.Cipher import AES	#pycrypto
from pcapy import open_live

# testing imports:
import binascii


	# Global vars defines, defaults
iface = "wlan1"
driver = "rtl8187"
chan = 6
modulus = 3.6
remainder = 1.2
	# for AES 256 the key has to be 32 bytes long.
AESkey = "B" * 32
	# for code that sets new key:
	# password = 'kitty'
	# key = hashlib.sha256(password).digest()
		
class AEScrypt():
	# much of this is taken from this how-to: 
	# http://www.codekoala.com/blog/2009/aes-encryption-python-using-pycrypto/
	# http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
	
	# How the IV is transmited: 
	# [ - - - 16B - - - -][ 2B ][ - - - - NB - - - - - -]
	# first 16 bytes for the message is the IV. 
	# bytes 17 and 18 are the number of blocks to read. (int short)

	def __init__(self):
		
		self.blockSize = 32
		# This padding byte needs to be changed because it could 
		# acidentally rstrip a few bytes of the real message (if the plaintext ends in a "A")
		self.padding = "A"
		self.mode = AES.MODE_CBC
		
	def encrypt(self, data):
		
		# returns a block of string of cipher text
		iv = os.urandom(16)
		encryptor = AES.new(AESkey, self.mode, iv)
		encoded = "%s" % (data + (self.blockSize - len(data) % self.blockSize) * self.padding)
		encoded = encryptor.encrypt(encoded)
		block_count = len(encoded) / 32
		block_count = struct.pack("H", block_count)
		output = iv + block_count + encoded
		return output
		
	def decrypt(self, data):
		
		# return a block of plaintext
		iv = data[:16]
		block_count = struct.unpack("H", data[16:18])
		block_count = block_count[0] * 32 + 18
		raw = data[18:block_count]
		encryptor = AES.new(AESkey, self.mode, iv)
		try:
			Eoutput = encryptor.decrypt(raw).rstrip(self.padding)
		except:
			print "Bad Packet legnth, consider resending"
			
		return Eoutput
		
class SendRec():
	
	def __init__(self):
		# initilize all that shit. 
		
		try:
			self.lorcon = pylorcon.Lorcon(iface, driver)
		except:
			print "Error creating lorcon object, try running as root"
			exit()
		
		# check for monitor mode, if not already in monitor mode, make it.
		if (self.lorcon.getmode() != "MONITOR"):
			os.system("ifconfig " + iface + " down");
			self.lorcon.setmode("MONITOR");
			os.system("ifconfig " + iface + " up");
		
		self.lorcon.setfunctionalmode("INJECT");
		self.lorcon.setchannel(chan);
		
		# Quick definitions for pcapy
		MAX_LEN      = 1514		# max size of packet to capture
		PROMISCUOUS  = 1		# promiscuous mode?
		READ_TIMEOUT = 0		# in milliseconds
		MAX_PKTS     = 1		# number of packets to capture; 0 => no limit
		try:
			self.pcapy = open_live(iface, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
		except:
			print "Error creating pcapy descriptor, try turning on the target interface or setting it to monitor mode"
	
	def updateChan(self, channel):
		self.lorcon.setchannel(channel)
	
	# These send/rec functions should be used in hidden / paranoid mode.
	def sendPacket(self, data):
		self.lorcon.txpacket(data)
	def recPacket(self):
		# return the raw packet if the mod/remain value is correct. 
		run = True 
		while(run):
			header, rawPack = self.pcapy.next()
			size = len(rawPack)
			if (size % modulus == remainder):
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
		while( round((len(data) + 13) % modulus, 2) != remainder):
			data = data + os.urandom(1);
		self.lorcon.txpacket(data)
	def recPacketDurFix(self):
		# return the raw packet if the mod/remain value is correct. 
		run = True 
		while(run):
			header, rawPack = self.pcapy.next()
			size = len(rawPack)
			if (round(size % modulus, 2) == remainder):
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
			if (size % modulus == remainder):
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
			
class TrafficModel():
	"""
	
	Builds a model of current traffic that can be used at a later time to make packets.
	
	"""
	data = []
	time = 3
	
	# In network byte order
	# If you do a lookup on this table and dont find a match it is probly
	# a 'reserved' type.
	Dot11_Types = {
		# management
		"assocReq": "\x00",
		"assocRes": "\x10",
		"reAssocReq": "\x20",
		"reAssocRes": "\x30",
		"probeReq": "\x40",
		"probeRes": "\x50",
		"beacon": "\x80",
		"ATIM": "\x90",
		"disAssoc": "\xa0",
		"auth": "\xb0",
		"deAuth": "\xc0",
		"action": "\xd0",

		# control
		"blockAckReq": "\x81",
		"blockAck": "\x91",
		"PSPoll": "\xa1",
		"RTS": "\xb1",
		"CTS": "\xc1",
		"ACK": "\xd1",
		"CFend": "\xe1",
		"CFendCFack": "\xf1",

		# data
		"data": "\x02",
		"data-CFAck": "\x12",
		"data-CFPoll": "\x22",
		"data-CFAckPoll": "\x32",
		"dataNULL": "\x42",
		"data-CFAckNULL": "\x52",
		"data-CFPollNULL": "\x62",
		"data-CFAckPollNULL": "\x72",
		"dataQOS": "\x82",
		"dataQOS": "\x88",
		"dataQOS-CFAck": "\x92",
		"dataQOS-CFPoll": "\xa2",
		"dataQOS-CFAckPoll": "\xb2",
		"dataQOSNULL": "\x82",  # wtf why?
		"dataQOS-CFPollNULL": "\xe2",
		"dataQOS-CFAckPollNULL": "\xf2",
	}
	
	# Model attributes:
	# -Type ranges
	# -MAC addresses
	# -
	
	type_ranges = []
	mac_addresses = []
	
	def __init__(self):
		self.interface = SendRec()
		self.collectData()
		self.stripRadioTap()
		self.extractModel()
		
	def collectData(self):
		"""
		
		Collect packets for the pre determined amount of time.
		
		"""
		start_time = time.time()
		current_time = start_time
		while ( (current_time - start_time) < self.time):
			packet = self.interface.recvRaw()
			self.data.append(packet)
			current_time = time.time()
	
	def stripRadioTap(self):
		"""
		Strips the RadioTap header info out of the packets are replaces the data 
		list with the new packets.
		"""
		temp_data = []
		for packet in self.data:
			sizeHead = struct.unpack("<H", packet[2:4])
			temp_data.append(packet[sizeHead[0]:])
		self.data = temp_data
	
	# For Debugging 
	# 
	#def showData(self):
	#	print "Packets: "
	#	for packet in self.data:
	#		print binascii.hexlify(packet)
	#		print ""
	#	print "Packet Count: " + str(len(self.data))

	def rawToType(self, type_raw):
		"""
		
		input the byte and return a string of the 802.11 type
		
		"""
		for k,v in self.Dot11_Types.iteritems():
			if (v == type_raw[0]):
				return k
		return "reserved (" + binascii.hexlify(type_raw[0]) + ")"
	
	def buildModelTypes(self, graphs):
		"""
		
		Adds the extracted types and %'s to the model
		
		"""
		count = 0.0
		for type in graphs:
			count += type[1]
		for type in graphs:
			self.type_ranges.append( [type[0], (type[1] / count)] )
			
	def buildModelAddresses(self, addresses):
		""""
		
		Adds the extracted addresses and %'s to the model
		
		"""
		count = 0.0
		for addr in addresses:
			count += addr[1]
		for addr in addresses:
			self.mac_addresses.append( [addr[0], (addr[1] / count)])
	def extractModel(self):
		"""
		
		Loops through all collected packets and creates different aspects of the model
		
		"""
		graphs = []
		addresses = []
	
		# loop through all packets, then loop through all types,
		# append if the type is not found,
		# inrement count if it is.
		for packet in self.data:
			
			# addresses[addr, count]
			# model common mac addresses used
			mac = packet[10:15]
			found = False
			for addr in addresses:
				if (mac == addr[0]):
					addr[1] = addr[1] + 1
					found = True
			if(found == False):
				addresses.append([mac, 1])
			
			# graphs[type, count]
			type = packet[:1]
			found = False
			for types in graphs:
				if (type == types[0]):
					types[1] = types[1] + 1
					found = True
			if(found == False):
				graphs.append([type, 1])
		
		# sort by count		
		graphs.sort(key=operator.itemgetter(1), reverse=True)
		addresses.sort(key=operator.itemgetter(1), reverse=True)
		
		self.buildModelTypes(graphs)
		self.buildModelAddresses(addresses)
		
	# debugging:
	def printTypes(self):
		"""
		
		Prints out a list of the packet types and percentages in the model
		
		"""
		print "%-15s%s" % ("Type", "Percent")
		print "-" * 20
		for entry in self.type_ranges:
			print "%-15s%f" % (self.rawToType(entry[0]), entry[1])

	def printMacs(self):
		"""
		
		Prints out a list of src mac address and percentages in the model
		
		"""
		print "\n%-15s%s" % ("Addr", "Percent")
		print "-" * 20
		for entry in self.mac_addresses:
			print "%-15s%f" % (binascii.hexlify(entry[0]), entry[1])

	def getValueFrom(self, array):
		"""
		
		Returns a value (such as a MAC addr or packet type) from the model of the given list.
		Follows the [name, value] structure.
		
		"""
		num = random.random()
		count = 0.0
		for entry in array:
			count += entry[1] 
			if count > num:
				break
		return entry[0];

# test traffic mapping
test_map = TrafficModel()
print "\nChannel: %s" % chan

test_map.printTypes()
test_map.printMacs()

test_map.mac_addresses = []
test_map.type_ranges = []
test_map.data = []


#crypter = AEScrypt()
#output = crypter.encrypt("HELLO WORLD" * 30)
#print "chiphertext: %s" % binascii.hexlify(output)
#print "chiphertext length: %s" % len(output);
#sandr = SendRec()
#sandr.sendPacketDurFix(output)
#input = sandr.recPacketDurFix()
#result = crypter.decrypt(input)
#print "plaintext:   %s" % result

#sandr = SendRec()
#sandr.sendPacketDurFix("HELLO LOVELY WOMAN")
#input = sandr.recPacketDurFix()
#print input

#object = SendRec()
#object.start()
#object.reloop()
