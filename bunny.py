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
import sys, os
import base64
import time

import pylorcon
from Crypto.Cipher import AES	#pycrypto
from pcapy import open_live

	# Global vars defines, defaults
iface = "wlan1"
driver = "rtl8187"
chan = 6
	# for AES 256 the key has too be 32 bytes long.
AESkey = "A" * 32
	# for code that sets new key:
	# password = 'kitty'
	# key = hashlib.sha256(password).digest()

class Spoof80211():
	
# end of Spoof80211 class

class Crypto():
	# much of this is taken from this how-to: 
	# http://www.codekoala.com/blog/2009/aes-encryption-python-using-pycrypto/
	# http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
	
	# TODO:
	# 1. Initilize the encryptor object with proper IV
	# 2. Make the data into proper block sizes.
	# 3. working crypt/decrypt functions
	# 4. TESTING!
	def __init__(self)
		self.BlockSize = 32
		self.PADDING = "A"
		mode = MODE_CBC
		self.encryptor = AES.new(AESkey, mode)
	def crypt(data):
		
	def decrypt(data):
	
# end of Crypto class

class SendRec():
	def sendPck(self, data):
		
	def recPck(self):
		
	def start(self):
		try:
			self.lorcon = pylorcon.Lorcon(iface, driver)
		except:
			print "error creating lorcon object"
		self.lorcon.setfunctionalmode("INJECT");
		self.lorcon.setmode("MONITOR");
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
	
	# This exists only for testing purposes.
	# Too ensure proper packets are read properly and at a high enough rate. 
	def reloop(self):
		count = 0
		packNum = 2000
		startTime = time.time()
		for n in range(packNum):
			header, rawPack = self.pcapy.next()
			size = len(rawPack)
			if (size % 4 == 0):
				print "pack num: %d, length is divisible by 4" % n  
		endTime = time.time()
		totalTime = endTime - startTime
		packPerSec = packNum / totalTime
		print "Total Packets (p/s): %s" % packPerSec

# end of sendRec Class

class Bunny():
	
# end of Bunny class

bunny = Bunny()
bunny.start("wlan1", "rtl8187", 6)
#bunny.send("AAAAAHELLOAAAAA", 2000)
bunny.reloop()

print "Done"
