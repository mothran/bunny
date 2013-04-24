#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#    bunny.py
#
#    Copyright 2013 W. Parker Thompson <w.parker.thompson@gmail.com>
#		
#    This file is part of Bunny.
#
#    Bunny is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Bunny is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Bunny.  If not, see <http://www.gnu.org/licenses/>.

import os, binascii, struct

from Crypto.Cipher import AES	#pycrypto
from config import *

class AEScrypt:
	"""
	
	Class for encrypting and decrypting AES256 data.
	
	"""
	
	# much of this is taken from this how-to: 
	# http://www.codekoala.com/blog/2009/aes-encryption-python-using-pycrypto/
	# http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/
	
	#TODO:
	# MAC, possibly use pyocb module to provide AES-OCB, thus getting Message auth,
	# Needs more research though.
	# or 
	# CCM, less patents.
	
	# How the IV is transmited: 
	# [ - - - 16B - - - -][ 2B ][ - - - - NB - - - - - -]
	# first 16 bytes for the message is the IV. 
	# bytes 17 and 18 are the number of blocks to read. (int short)

	def __init__(self):
		
		self.blockSize = 32
		# This padding byte needs to be changed because it could 
		# acidentally rstrip a few bytes of the real message (if the plaintext ends in a "A")
		# TODO: "N bytes of a value of N" padding to prevent this issue.
		self.padding = "A"
		self.mode = AES.MODE_CBC
		self.aes_key = binascii.unhexlify(AESKEY)
		
	def encrypt(self, data):
		
		# returns a block of string of cipher text
		iv = os.urandom(16)
		encryptor = AES.new(self.aes_key, self.mode, iv)
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
		encryptor = AES.new(self.aes_key, self.mode, iv)
		try:
			Eoutput = encryptor.decrypt(raw).rstrip(self.padding)
		except:
			print "Bad Packet legnth, consider resending"
			return False
			
		return Eoutput
		
