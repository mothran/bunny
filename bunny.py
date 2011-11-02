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
import sys, os, time, base64, struct

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
modulus = 4.5
remainder = 3.5
	# for AES 256 the key has too be 32 bytes long.
AESkey = "B" * 32
	# for code that sets new key:
	# password = 'kitty'
	# key = hashlib.sha256(password).digest()


class AEScrypt():
	# much of this is taken from this how-to: 
	# http://www.codekoala.com/blog/2009/aes-encryption-python-using-pycrypto/
	# http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
	
	# How the IV is transmited: 
	# [ - - - 16B - - - -][ - - - - NB - - - - - -]
	# first 16 bytes for the message is the IV. 


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
		encoded = "%s%s" % (iv, (data + (self.blockSize - len(data) % self.blockSize) * self.padding))
		
		# we might want to remove the base64 encoding for when it is actually on air.
		return base64.b64encode(encryptor.encrypt(encoded))
		
	def decrypt(self, data):
		
		# return a block of plaintext 
		output = base64.b64decode(data)
		iv = output[:16]
		raw = output[16:]
		encryptor = AES.new(AESkey, self.mode, iv)
		return encryptor.decrypt(raw).rstrip(self.padding)
	
# end of Crypto class

class SendRec():
	
	# These send/rec functions should be used in hidden / paranoid mode.
	def sendPacket(self, data):
		# send dat shit!
		self.lorcon.txpacket(data)
	def recPacket(self):
		# return the raw packet if the mod/remain value is correct. 
		run = True 
		while(run):
			header, rawPack = self.pcapy.next()
			size = len(rawPack)
			if (size % modulus == remainder):
				run = False
					# fmt:
					#	H = unsigned short
				size = struct.unpack("<H", rawPack[2:4])
				size = int(size[0])
				rawPack = rawPack[size:]
				return rawPack
	
	# these functions should be used if you dont care about being noticed
	def sendPacketDurFix(self, data):
		data = "\x00\x00\x00\x00" + data
		self.lorcon.txpacket(data)
	
	def recPacketDurFix(self):
		# return the raw packet if the mod/remain value is correct. 
		run = True 
		while(run):
			header, rawPack = self.pcapy.next()
			size = len(rawPack)
			if (size % modulus == remainder):
				run = False
					# fmt:
					#	H = unsigned short
				sizeHead = struct.unpack("<H", rawPack[2:4])
				sizeHead = int(sizeHead[0]) + 4
				rawPack = rawPack[sizeHead:]
				return rawPack
	
		
	def start(self):
		# initilize all that shit. 
		# might consider moving this to a def: __init__
		
		try:
			self.lorcon = pylorcon.Lorcon(iface, driver)
		except:
			print "Error creating lorcon object, try running as root"
			exit()
		self.lorcon.setmode("MONITOR");
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
	
	def reloop(self):
		# This exists only for testing purposes.
		# Too ensure proper packets are read properly and at a high enough rate. 
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

# end of sendRec Class

#crypter = AEScrypt()
#output = crypter.encrypt("Hello world")
#print "chiphertext: %s" % output
#result = crypter.decrypt(output)
#rint "plaintext:   %s" % result

sandr = SendRec()
sandr.start()
sandr.sendPacketDurFix("HELLO LOVELY WOMAN")
input = sandr.recPacketDurFix()
print input
