#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       bunny.py
#       
#       Copyright 2011 Parker Thompson <w.parker.thompson@gmail.com>
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

import threading, Queue, binascii

from AEScrypt import *
#from configure import *
from SendRec import *
from Templates import *
from TrafficModel import *
from config import *

class Bunny:
	"""
	
	High level send and recive for wrapping all the lower function of bunny in paranoid mode.
	
	"""
	
	def __init__(self):
		"""
		
		Setup and build the bunny model and starts the read_packet_thread()
		
		"""
		
		self.inandout = SendRec()
		self.cryptor = AEScrypt()
		self.model = TrafficModel()
		
		# each item in should be an full bunny message that can be passed to the .decrypt() method
		# TODO: put a upper bound of number of messages or a cleanup thread to clear out old messages
		# 		if not consumed.
		self.msg_queue = Queue.LifoQueue()
		
		workers = [BunnyReadThread(self.msg_queue, self.inandout, self.cryptor, self.model)]
		for worker in workers:
			worker.daemon = True
			worker.start()
		
	def sendBunny(self, packet):
		"""
		
		Send a Bunny (paranoid) packet
		
		"""
		
		packet = self.cryptor.encrypt(packet)
		if DEBUG:
			print "CypherText: " + binascii.hexlify(packet)
			print "blocks: " + binascii.hexlify(packet[16:18])
		
		while ( len(packet) != 0 ):
			#TIMING
			#start_t = time.time()
			entry = self.model.getEntryFrom(self.model.type_ranges)
			try:
				outpacket = entry[2].makePacket(packet[:entry[3]])
				if DEBUG:
					print "Sending with: %s" % self.model.rawToType(entry[0])
					print "length: " + str(len(outpacket))
				
			except AttributeError:
				continue
			packet = packet[entry[3]:]
			self.inandout.sendPacket(outpacket)

	def recvBunny(self, timer=False):
		"""
		
		Grab the next bunny message in the queue and decrypt it and return the plaintext message
		
		Arg: timer
			If not false, bunny will timeout in the number of seconds in timer
		
		Returns:
			Decrypted bunny message or if timedout, False
		
		"""
		if timer:
			try:
				data = self.msg_queue.get(True, timer)
			except Queue.Empty:
				return False
		else:
			data = self.msg_queue.get()

		self.msg_queue.task_done()
		return self.cryptor.decrypt(data)
		
	
class BunnyReadThread(threading.Thread):

	def __init__(self, queue, ioObj, cryptoObj, model):
		self.msg_queue = queue
		self.inandout = ioObj
		self.cryptor = cryptoObj
		self.model = model
		threading.Thread.__init__(self)

	def run(self):
		blockget = False
		decoded = ""
		
		while True:
			# declare / clear the type array.
			type = []
	
			try:						
				encoded = self.inandout.recPacket_timeout(self.model.FCS)
				#TIMING
				#start_t = time.time()
			except TimeoutWarning:
				blockget = False
				decoded = ""
				continue
			
			if DEBUG:
				print "\nHit packet"
			
			if DEBUG:
				print "Type: %s\t Raw: %s" % (binascii.hexlify(encoded[0:1]), self.model.rawToType(encoded[0:1]))
			
			for entry in self.model.type_ranges:
				if entry[0] == encoded[0:1]:
					if entry[3] > 0:
						# check so that the injectable length is over 0
						type = entry
						break
			
			if len(type) < 2:
				if DEBUG:
					print "Packet type not in templates"
				
				entry = self.model.insertNewTemplate(encoded)
				if entry is not False:
					if DEBUG:
						print "successfuly inserted template"
					self.model.type_ranges.append(entry)
					type = entry
				else:
					if DEBUG:
						print "Packet type not implemented"
					continue
			
			# decode the bunny packet
			temp = type[2].decode(encoded)
			if DEBUG:
				print "CypherText: " + binascii.hexlify(temp)
			
			if temp is False:
				if DEBUG:
					print "decoding fail"
				continue
			else:
				decoded_len = len(decoded)
				if decoded_len < 18:
					decoded = decoded + temp
				else:
					if blockget == False:
						blocks, = struct.unpack("H", decoded[16:18])
						
						if DEBUG:
							print "blocks: " + str(blocks)
						blockget = True
						decoded = decoded + temp
						decoded_len = len(decoded)
					elif decoded_len < (32*blocks + 18):
						decoded = decoded + temp
						decoded_len = len(decoded)
					if decoded_len >= (32*blocks + 18):
						# might be redundant
						if DEBUG:
							print "Adding message to Queue"
						#TIMING
						#print "recv time: %f" % (time.time() - start_t)
						self.msg_queue.put(decoded)
						
						# clean up for the next loop
						blockget = False
						decoded = ""
				#TIMING
				#print "recv time: %f" % (time.time() - start_t)
