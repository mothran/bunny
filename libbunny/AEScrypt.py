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
		
