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
import sys, os, time, struct, operator, random, ConfigParser, hashlib, threading, getpass

# depends:
import pylorcon
from Crypto.Cipher import AES	#pycrypto
from pcapy import open_live

# testing imports:
import binascii


class Configure:
	"""
	
	Makes and reads the 'bunny.conf' file where all global varibles are held.
	
	"""
	
	def __init__(self):
		"""
		
		Reads the config file, if the file does not exist, create it with defaults.
		
		"""
		
		# All config varibles are global varibles.
		global AESkey
		global caplength
		global chan
		global iface
		global driver
		global modulus
		global remainder
		global timeout
		global username
		
		config = ConfigParser.RawConfigParser()
		try:
			config.readfp(open("bunny.conf"))
		except IOError:
			self.makeConfig()
			config.readfp(open("bunny.conf"))
		
		# grab the config varibles, if one is not found, write out the config
		AESkey = binascii.unhexlify(config.get("AES", "key"))
		
		caplength = config.getint("trafficModel", "caplength")
		
		chan = config.getint("readWrite", "channel")
		iface = config.get("readWrite", "interface")
		driver = config.get("readWrite", "driver")
		modulus = config.getfloat("readWrite", "modulus")
		remainder = config.getfloat("readWrite", "remainder")
		timeout = config.getint("readWrite", "timeout")
		
		username = config.get("chatClient", "username")
	def makeConfig(self):
		"""
		
		These defaults are know working values, PLEASE CHANGE THEM.
		
		"""
		config = ConfigParser.RawConfigParser()
		
		config.add_section("AES")
		config.set("AES", "key", hashlib.sha256("B"*32).hexdigest() )
		
		config.add_section("trafficModel")
		config.set("trafficModel", "caplength", 3)
		
		config.add_section("readWrite")
		config.set("readWrite", "channel", 8)
		config.set("readWrite", "interface", "wlan1")
		config.set("readWrite", "driver", "rtl8187")
		config.set("readWrite", "modulus", 1.23)
		config.set("readWrite", "remainder", 0.82)
		config.set("readWrite", "timeout", 5)
		
		config.add_section("readWrite")
		config.set("chatClient", "username", getpass.getuser())
		
		with open("bunny.conf", 'wb') as configfile:
			config.write(configfile)
	
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
			return False
			
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
	
	class Beacon:
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
				
			#self.SSID = self.tagGrabber("\x00")
			
			# design problem here, after attempting dynamic lengths for the injection
			# fields I relized that for interconnectivity between clients I need to hardcode
			# injection lengths.  So the vendor tag is 24 bytes of data:
			self.injectable = 24 + 2 + 2
			
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
			outbound = outbound + "\xdd" + struct.pack("<B", len(inject_data[4:])) + inject_data[4:]
			#outbound += struct.pack("!i", zlib.crc32(outbound))
			
			outbound = self.resize(outbound)
			#print "len of injectedBEACON: %d" % len(inject_data)
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
			
			#print len(outpack)
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
			
			# Fail design:
			#if value_chunk == self.tags[len(self.tags)-2]:
			#	return False
			
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
		
		Template to hold a example Data packet type, currently we only support simple LLC
		packets for injection, encrypted data needs to be included.
		
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
			self.QOS = packet[24:26]
			self.databody = packet[26:]
			
			# FIX THIS:
			# Temp size is 40 bytes
			self.injectable = 2 + 40
			
		def makePacket(self, inject_data):
			"""
			
			Make a QOS data packet with injected data, fields are: Sequence num and databody
			
			"""
			outbound = self.type + self.frame_control + self.duration+ self.BSSID + self.SA + self.DA + inject_data[0:2] + self.QOS
			
			outbound = outbound + struct.pack("B", len(inject_data[2:])) + inject_data[2:]
			
			outbound = self.resize(outbound)
			return outbound
			
		def resize(self, outpack):
			
			while(round( (len(outpack) + 13) % modulus, 2) != remainder):
				outpack = outpack + os.urandom(1)
			return outpack
			
		def decode(self, input):
			# read the databody up to the size of the byte of length
			size, = struct.unpack("B", input[26:27])
			output = input[22:24] + input[27:size+27]
			return  output		
	class ProbeRequest:
		"""
		
		ProbeRequst packet type template, injectable fields are sequence number and SSID.
		
		"""
		injectable = 0
		tags = []
		vendors = []
		
		type = ""
		frame_control = ""
		duration = ""
		BSSID = ""
		SA = ""
		DA = ""
		sequence_num = ""
		
		def __init__(self, packet):
			# For a speed up we could use the struct.unpack() method
			# self.type, self.frame_control, struct.unpack("", packet)
			self.type = packet[0:1]
			self.frame_control = packet[1:2]
			self.duration = packet[2:4]
			self.DA = packet[4:10]
			self.SA = packet[10:16]
			self.BSSID = packet[16:22]
			self.sequence_num = packet[22:24]
			
			packet = packet[24:]
			
			while (len(packet) != 0):
				id = packet[:1]
				length, = struct.unpack("B", packet[1:2])
				value = packet[2:length+2]
				self.tags.append([id, length, value])
				if id == "\xdd":
					self.vendors.append([value[:3]])
				packet = packet[length + 2:]
				
			# ProbeRequests get the data injected into the ssid's
			# and are resized by a vendor tag, default SSID length is 12, again 
			# possibly signatureable.
			self.injectable = 12 + 2
			
		def makePacket(self, inject_data):
			"""
			
			Creates a packet with injected encrypted data.
			
			"""
			
			outbound = self.type + self.frame_control + self.duration + self.DA + self.SA + self.BSSID + inject_data[0:2]
			outbound = outbound + "\x00" + struct.pack("<B", len(inject_data[2:])) + inject_data[2:] 
			for i in range(1, len(self.tags)-1):
				outbound = outbound + self.tags[i][0] + struct.pack("<B", self.tags[i][1]) + self.tags[i][2]

			return self.resize(outbound)
		def resize(self, outpack):
			"""
			
			Resizes the packet with the proper mod / remainder value
			Uses last vendor tag.
			
			"""
			# counter will be the size of the tag
			# using \xdd for vendor tag.
			if len(self.vendors) == 0:
				tag = ["\xdd", 0, os.urandom(3)]
			else:
				tag = ["\xdd", 0, self.vendors[random.randrange(0, len(self.vendors))][0]]
			
			while( round( (len(outpack) + tag[1] + 2 + 13) % modulus, 2) != remainder):
				tag[2] = tag[2] + os.urandom(1)
				tag[1] = len(tag[2])
			outpack = outpack + tag[0] + struct.pack("<B", tag[1]) + tag[2]
			return outpack
		
		def decode(self, input):
			"""
			
			Decodes the encrypted data out of the inputed packet
			
			"""
			
			output = input[22:24]
			temp_tags = []
			
			input = input[24:]
			while (len(input) != 0):
				id = input[:1]
				length, = struct.unpack("B", input[1:2])
				value = input[2:length+2]
				temp_tags.append([id, length, value])
				input = input[length + 2:]
			value_chunk = temp_tags[0][2]
			return output + value_chunk
			
		def tagGrabber(self, id):
			"""
			
			return the whole tag from an array of tags by its tag id
			
			"""
			for entry in self.tags:
				if (entry[0] == id):
					return entry
					
class TrafficModel():
	"""
	
	Builds a model of current traffic that can be used at a later time to make packets.
	
	"""
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
		"""
		
		Starts up the model, collects data and inserts it into its respective lists
		
		"""
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
		
		# caplength is a glocal var from config.
		while ( (current_time - start_time) < caplength):
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
			if (type == "probeReq"):
				entry[2] = Templates.ProbeRequest(entry[2])
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

class TimeoutWarning():
	"""
	
	Homebrew Exception class for packet reading timeouts
	The timeout config global varible is related to when this class is used.
	
	"""
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return self.value

class Bunny:
	"""
	
	High level send and recive for wrapping all the lower function of bunny in paranoid mode.
	
	"""
		
	def __init__(self):
		"""
		
		Setup and build the bunny model
		
		"""
		
		self.config = Configure()
		self.inandout = SendRec()
		self.cryptor = AEScrypt()
		self.model = TrafficModel()
		
	def sendBunny(self, packet):
		"""
		
		Send a Bunny (paranoid) packet
		
		"""
		
		packet = self.cryptor.encrypt(packet)
		while ( len(packet) != 0 ):
			entry = self.model.getEntryFrom(self.model.type_ranges)
			try:
				outpacket = entry[2].makePacket(packet[:entry[3]])
				# Debugging info
				#print "Sending with: %s" % self.model.rawToType(entry[0])
			except AttributeError:
				continue
			packet = packet[entry[3]:]
			self.inandout.sendPacket(outpacket)

	def recvBunny(self):
		"""
		
		Read and decode loop for bunny, raises a TimeoutWarning if it times out.
		
		"""
		
		# Standard calling should look like this:
		#	try:
		#		print bunny.recvBunny()
		#	except TimeoutWarning:
		#		pass
		
		run = True
		blockget = False
		type = []
		decoded = ""
		
		while run:								
			encoded = self.inandout.recPacket()
			first_time = time.time()
			for entry in self.model.type_ranges:
				if entry[0] == encoded[0:1]:
					if entry[3] > 0:
						type = entry
			if len(type) < 2:
				continue
			temp = type[2].decode(encoded)
			if temp is False:
				continue
			else:
				if (time.time() - first_time) > timeout:
					print "Timeout hit: %d" % (current_time - first_time)
					raise TimeoutWarning("The read timed out")
					break
				decoded_len = len(decoded)
				if decoded_len < 18:
					decoded = decoded + temp
				else:
					if blockget == False:
						blocks, = struct.unpack("H", decoded[16:18])
						blockget = True
						decoded = decoded + temp
						decoded_len = len(decoded)
					elif decoded_len < (32*blocks + 18):
						decoded = decoded + temp
						decoded_len = len(decoded)
					if decoded_len >= (32*blocks + 18):
						# might be redundant
						run = False
						break
		return self.cryptor.decrypt(decoded)

# quick and dirty threading for the send/rec chat client mode.
class StdInThread(threading.Thread):
	"""
	
	Thread class for reading from STDIN
	
	"""
	# takes the bunny object as an argument
	def __init__(self, bunny):
		self.bunny = bunny
		threading.Thread.__init__(self)
	def run (self):
		print "ready to read! (type: /quit to kill)"
		while 1:
			input = sys.stdin.readline().strip("\n")
			if input == "/quit":
				break
			# send with username and a trailer to prevent the stripping of 'A's as padding
			# see the comment in the __init__() in AEScrypt
			self.bunny.sendBunny(username + ": " + input + "\xff")
			
class BunnyThread(threading.Thread):
	"""
	
	Thread class for reading from the bunny interface
	
	"""
	# takes the bunny object as an argument
	def __init__(self, bunny):
		self.bunny = bunny
		threading.Thread.__init__(self)
	def run (self):
		# Standard calling should look like this:
		while 1:
			try:
				text = self.bunny.recvBunny()
				
				# if we get our own username do not display it,
				# FIX THIS
				if text.split(":")[0] == username:
					continue
				else:
					# strip out the ending char.
					print text.rstrip("\xff")
			except TimeoutWarning:
				pass

def usage():
	"""
	
	print out usage
	
	"""
	print "Bunny.py [COMANDS]"
	print "-l\t\t--\tListen mode, gets packets and prints data"
	print "-s [data]\t--\tSend mode, sends packets over and over"
	print "-m\t\t--\tPassive profiling of all the channels (1-11)"
	print "-c\t\t--\tChat client mode"
	
def main():
	"""
	
	main func, needs better argument handeling.
	
	"""
	
	if len(sys.argv) < 2:
		usage()
		sys.exit()
	if sys.argv[1] == "-l":
		print "Bunny in listen mode"
		print "Building model: . . . "
		bunny = Bunny()
		print "Bunny model built and ready to listen"
		while True:
			try:
				print bunny.recvBunny()
			except TimeoutWarning:
				pass
	elif sys.argv[1] == "-s":
		if sys.argv[2] is not None:
			bunny = Bunny()
			print "Bunny model built"
			bunny.model.printTypes()
			bunny.model.printMacs()
			print "sending message: %s" % sys.argv[2]
			bunny.sendBunny(sys.argv[2])
			
			while True:
				print "again? [Y/N]"
				input = sys.stdin.readline()
				if input == "Y\n" or input == "y\n":
					print "sending message: %s" % sys.argv[2]
					bunny.sendBunny(sys.argv[2])
				elif input == "N\n" or input == "n\n":
					sys.exit()
		else:
			print usage()
			sys.exit()
	elif sys.argv[1] == "-c":
		print "chat client mode:"
		print "building traffic model: . . "
		bunny = Bunny()
		print "built traffic model!"
		bunny.model.printTypes()
		bunny.model.printMacs()
		print "starting threads: "
		
		# create list of threads
		# one thread for input and the other for output.
		# both use stdin or stdout
		workers = [StdInThread(bunny), BunnyThread(bunny)]
		
		for worker in workers:
			worker.setDaemon(True)
			worker.start()
		
		# loop through every 3 seconds and check for dead threads
		while True:
			for worker in workers:
				if not worker.isAlive():
					sys.exit()
			time.sleep(3)
		
	elif sys.argv[1] == "-m":
		for c in range(1,12):
			chan = c
			print "\nChannel: %d" % chan			
			bunny = Bunny()
			bunny.model.printTypes()
			#bunny.model.printMacs()
	else:
		usage()
		sys.exit()

if __name__ == "__main__":
	main()
