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
import sys, os, time, struct, operator, random, zlib

# depends:
import pylorcon
from Crypto.Cipher import AES	#pycrypto
from pcapy import open_live

# testing imports:
import binascii


	# Global vars defines, defaults
iface = "wlan1"
driver = "rtl8187"
chan = 1
modulus = 3.6
remainder = 1.2
	# for AES 256 the key has to be 32 bytes long.
AESkey = "B" * 32
	# for code that sets new key:
	# password = 'kitty'
	# key = hashlib.sha256(password).digest()
		
class AEScrypt:
	"""
	
	Class for encrypting and decrypting AES256 data.
	
	"""
	
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
		
class SendRec:
	"""
	
	Main IO functionality of bunny, using pcapy and lorcon to do send and receive.
	
	"""
	def __init__(self):		
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
		if data is not None:
			self.lorcon.txpacket(data)
	def recPacket(self):
		# return the raw packet if the mod/remain value is correct. 
		run = True 
		while(run):
			header, rawPack = self.pcapy.next()
			size = len(rawPack)
			if (round(size % modulus, 2) == remainder):
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

class Templates:
	"""
	
	Contains templates for all packet types used by bunny.
	
	"""
	class Beacon ():
		"""
		
		Template for Beacon packet types.  Initialize the template with a raw packet dump 
		of a beacon packet.
		
		"""
		# declares the number of bytes of communication this template can hold for a single injection
		injectable = 0
		
		type = ""
		frame_control = ""
		duration = ""
		BSSID = ""
		SA = ""
		DA = ""
		sequence_num = ""
		QOS = ""
		
		timestamp = ""
		beacon_interval = ""
		capability = ""
		
		# an array for taged fields 
		# tag [tagID, length, value]
		tags = []
		
		# a list of vendors found
		vendors = []
		
		SSID = ""

		def __init__(self, packet):
			# For a speed up we could use the struct.unpack() method
			#self.type, self.frame_control, struct.unpack("", pack_data)
			self.type = packet[0:1]
			self.frame_control = packet[1:2]
			self.duration = packet[2:4]
			self.BSSID = packet[4:10]
			self.SA = packet[10:16]
			self.DA = packet[16:22]
			self.sequence_num = packet[22:24]
			#self.RS = packet[21:26]
			self.timestamp = packet[24:32]
			self.beacon_interval = packet[32:34]
			self.capability = packet[34:36]
			
			packet = packet[36:]
			
			# Simple command to debug the current var's of this object.
			# print self.__dict__.keys()
			
			# loop through the tags and SAP them off into in the tags array
			# also appends any vendor OUI's into the vendors list.
			while (len(packet) != 0):
				id = packet[:1]
				length, = struct.unpack("B", packet[1:2])
				value = packet[2:length+2]
				self.tags.append([id, length, value])
				if id == "\xdd":
					self.vendors.append([value[:3]])
				packet = packet[length + 2:]
				
			self.SSID = self.tagGrabber("\x00")
			
			self.injectable = self.tags[len(self.tags) - 2][1] + 4
			
		def makePacket(self, inject_data):
			"""
			
			Creates and returns a beacon packet from the inject_data input
			inject_data must be of length Beacon.injectable
			
			injectable fields are:
			sequence_number, capabilities, 2nd to last vendor tags.
			
			"""
			# timestamp needs more testing.
			outbound = self.type + self.frame_control + self.duration + self.BSSID + self.SA + self.DA + inject_data[0:2] + self.timestamp + self.beacon_interval + inject_data[2:4]
			
			for i in range(0, len(self.tags)-2):
				outbound = outbound + self.tags[i][0] + struct.pack("<B", self.tags[i][1]) + self.tags[i][2]
			outbound = outbound + "\xdd" + struct.pack("<B", self.injectable - 4) + inject_data[4:]
			#outbound += struct.pack("!i", zlib.crc32(outbound))
			
			outbound = self.resize(outbound)
			
			return outbound
		def resize(self, outpack):
			"""
			
			Resizes the packet with the proper mod / remainder value
			
			Primarly uses last vendor tag.
			
			"""
			# counter will be the size of the tag
			# using \xdd for vendor tag.
			tag = ["\xdd", 0, self.vendors[random.randrange(0, len(self.vendors))][0]]
			
			while( round((len(outpack) + tag[1] + 2 + 13) % modulus, 2) != remainder):
				tag[2] = tag[2] + os.urandom(1)
				tag[1] = len(tag[2])
			outpack = outpack + tag[0] + struct.pack("B", tag[1]) + tag[2]
			return outpack
		
		def decode(self, input):
			output = input[22:24]
			output = output + input[34:36]
			
			input = input[36:]
			
			temp_tags = []
			# loop through and grab the second to last vendor tag
			while (len(input) != 0):
				id = input[:1]
				length, = struct.unpack("B", input[1:2])
				value = input[2:length+2]
				temp_tags.append([id, length, value])
				input = input[length + 2:]
				
			value_chunk = temp_tags[len(temp_tags) - 2][2]
			output = output + value_chunk
			
			return output
			
		def tagGrabber(self, id):
			"""
			
			return the whole tag from an array of tags by its tag id
			
			"""
			for entry in self.tags:
				if (entry[0] == id):
					return entry
	class DataQOS:
		"""
		
		Template to hold a example Data packet type, currently we only support encrypted data packets.
		In the furture, unknown LLC encapilation types can be used with not encrypted modeled traffic.
				
		"""
		injectable = 0
		
		# 802.11
		type = ""
		frame_control = ""
		duration = ""
		BSSID = ""
		SA = ""
		DA = ""
		sequence_num = ""
		QOS = ""
		crypto = ""
		
		# LLC
		
		
		def __init__(self, packet):
			# For a speed up we could use the struct.unpack() method
			# self.type, self.frame_control, struct.unpack("", packet)
			self.type = packet[0:1]
			self.frame_control = packet[1:2]
			self.duration = packet[2:4]
			self.BSSID = packet[4:10]
			self.SA = packet[10:16]
			self.DA = packet[16:22]
			self.sequence_num = packet[22:24]
			#self.RS = packet[21:26]
			self.QOS = packet[24:26]
			self.crypto = packet[26:34]
			self.databody = packet[34:]
			
			self.injectable = 5 + len(self.databody)
			
		def makePacket(self, inject_data):
			"""
			
			Make a QOS data packet with injected data, fields are: Sequence num, crypto, databody
			
			"""
			outbound = self.type + self.frame_control + self.duration+ self.BSSID + self.SA + self.DA + inject_data[0:2]
			outbound = outbound + self.QOS + inject_data[2:5] + self.crypto[3:] + inject_data[5:]
			
			outbound = self.resize(outbound)
			
		def resize(self, outpack):
			
			while(round( (len(outpack) + 13) % modulus, 2) != remainder):
				outpack = outpack + os.urandom(1)
			return outpack
			
		def decode(self, input):
			# read the databody up to inject_data - 5
			return  input[22:24] + input[26:29] + input[34:self.injectable-5]
		
class TrafficModel():
	"""
	
	Builds a model of current traffic that can be used at a later time to make packets.
	
	"""
	
	# the time used for capturing a model of the 802.11 traffic
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
		"ACK": "\xd4",
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
	# raw packets
	data = []
	
	# [type, freq, template, injectlen]
	type_ranges = []
	
	# [addr, freq, AP(bool)]
	mac_addresses = []
	
	def __init__(self):
		# clear any old data
		self.mac_addresses = []
		self.type_ranges = []
		self.data = []
		
		# spin up and build the model
		self.interface = SendRec()
		self.collectData()
		self.stripRadioTap()
		self.extractModel()
		self.insertTemplates()
			
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
			type[1] = (type[1] / count)
			self.type_ranges.append(type)
					
	def buildModelAddresses(self, addresses):
		""""
		
		Adds the extracted addresses and %'s to the model
		
		"""
		count = 0.0
		for addr in addresses:
			count += addr[1]
		for addr in addresses:
			addr[1] = (addr[1] / count)
			self.mac_addresses.append(addr)
			
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
			beacon = False
			
			# graphs[type, count]
			type = packet[:1]
			
			# check if its a beacon packet
			if(type == self.Dot11_Types['beacon']):
				beacon = True
			found = False
			for types in graphs:
				if (type == types[0]):
					types[1] = types[1] + 1
					found = True
			if(found == False):
				graphs.append([type, 1, packet, 0])
			
			
			# addresses[addr, count, AP?]
			# model common mac addresses used
			mac = packet[10:15]
			
			found = False
			for addr in addresses:
				if (mac == addr[0]):
					addr[1] = addr[1] + 1
					found = True
			if(found == False):
				if (beacon == True):
					addresses.append([mac, 1, True])
				else:
					addresses.append([mac, 1, False])
		
		# sort by count		
		graphs.sort(key=operator.itemgetter(1), reverse=True)
		addresses.sort(key=operator.itemgetter(1), reverse=True)
		
		self.buildModelTypes(graphs)
		self.buildModelAddresses(addresses)
		
	def insertTemplates(self):
		"""
		
		loops through the type_ranges list and replaces the raw packet data with template objects
		type_ranges becomes:
		[type, freq, templateObject, injectLen]
		
		"""
		for entry in self.type_ranges:
			type = self.rawToType(entry[0])
			if (type == "beacon"):
				# replace raw data with object of template type, then append the injection length
				entry[2] = Templates.Beacon(entry[2])
				entry[3] = entry[2].injectable
			if (type == "data" or type == "dataQOS"):
				entry[2] = Templates.DataQOS(entry[2])
				entry[3] = entry[2].injectable
			# add more
	# debugging:
	def printTypes(self):
		"""
		
		Prints out a list of the packet types and percentages in the model
		
		"""
		print "%-15s%s" % ("Type", "Percent")
		print "-" * 20
		for entry in self.type_ranges:
			print "%-15s%f" % (self.rawToType(entry[0]), entry[1])

	def printTypesWithPackets(self):
		"""
		
		Prints out a list of the packet types and percentages in the model
		
		"""
		print "%-15s%-10s%s" % ("Type", "Percent", "Template")
		print "-" * 30
		for entry in self.type_ranges:
			print "%-15s%-10f%s" % (self.rawToType(entry[0]), entry[1], binascii.hexlify(entry[2]))

	def printMacs(self):
		"""
		
		Prints out a list of src mac address and percentages in the model
		
		"""
		print "\n%-15s%-10s%s" % ("Addr", "Percent", "AP")
		print "-" * 30
		for entry in self.mac_addresses:
			print "%-15s%-10f%s" % (binascii.hexlify(entry[0]), entry[1], entry[2])

	def getEntryFrom(self, array):
		"""
		
		Returns a frequency adjusted random entry from an array such as type_ranges
		Follows the [name, freq, ...] structure.
		
		"""
		num = random.random()
		count = 0.0
		for entry in array:
			count += entry[1] 
			if count > num:
				break
		return entry;

class Bunny:
	"""
	
	High level send and recive for wrapping all the lower function of bunny in paranoid mode.
	
	"""
	
	def __init__(self):
		self.inandout = SendRec()
		self.cryptor = AEScrypt()
		self.model = TrafficModel()
		
	def sendBunny(self, packet):
		packet = self.cryptor.encrypt(packet)
		while ( len(packet) != 0 ):
			entry = self.model.getEntryFrom(self.model.type_ranges)
			try:
				outpacket = entry[2].makePacket(packet[:entry[3]])
			except AttributeError:
				continue
			packet = packet[entry[3]:]
			self.inandout.sendPacket(outpacket)
	def recvBunny(self):
		decoded = ""
		while(len(decoded) <= 18):
			encoded = self.inandout.recPacket()
			for type in self.model.type_ranges:
				if type[0] == encoded[0:1]:
					decoded = decoded + type[2].decode(encoded)
		blocks, = struct.unpack("H", decoded[16:18])
		while(len(decoded) <= blocks*32 + 18):
			encoded = self.inandout.recPacket()
			for type in self.model.type_ranges:
				if type[0] == encoded[0:1]:
					decoded = decoded + type[2].decode(encoded)
		return self.cryptor.decrypt(decoded)
		
# test traffic mapping
#test_map = TrafficModel()

print "\nChannel: %s" % chan

#test_map.printTypes()
#test_map.printMacs()

bunny = Bunny()
bunny.model.printTypes()
bunny.model.printMacs()

bunny.sendBunny("YODOG")
print bunny.recvBunny()

#test_map.interface.sendPacket(test_map.type_ranges[0][2].makePacket("HELLHELLO"))
#print test_map.type_ranges[0][2].decode(test_map.interface.recPacket())


#test_map.interface.updateChan(channel)
#print test_map.type_ranges[0][2].SSID
#test_map.getEntryFrom(type_ranges)


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
