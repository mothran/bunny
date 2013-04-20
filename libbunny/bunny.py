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

import threading, Queue, collections, binascii

from AEScrypt import *
#from configure import *
from SendRec import *
from Templates import *
from TrafficModel import *
from config import *


# So this is the heart and soul of bunny and also the biggest mess in the code base.
#  if anyone wants to look over my use of threads, queue and deques it would be lovely
#  to get some feedback and if anyone thinks there is a way to speed this up it would help.

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
		
		# The out queue is a FiFo Queue because it maintaines the ording of the bunny data
		self.out_queue = Queue.Queue()
		
		# The Deque is used because it is a thread safe iterable that can be filled with 'seen'
		# messages to between the send and recv threads. 
		self.msg_deque = collections.deque()
		
		workers = [BunnyReadThread(self.msg_queue, self.out_queue, self.inandout, self.model), BroadCaster(self.out_queue, self.msg_deque, self.inandout, self.model)]
		for worker in workers:
			worker.daemon = True
			worker.start()
		
		#TODO:?
		# can I add a 'isAlive()' checking loop here?
		
	def sendBunny(self, packet):
		"""
		
		Send a Bunny (paranoid) packet
		
		"""
		packet = self.cryptor.encrypt(packet)
		self.out_queue.put(packet)
		
	def recvBunny(self, timer=False):
		"""
		
		Grab the next bunny message in the queue and decrypt it and return the plaintext message
		
		Arg: timer
			If not false, bunny will timeout in the number of seconds in timer
		
		Returns:
			Decrypted bunny message or if timedout, False
		
		"""
		# this is looped just so if the message has been seen we can come back and keep trying.
		while True:
			if timer:
				try:
					data = self.msg_queue.get(True, timer)
				except Queue.Empty:
					return False
			else:
				data = self.msg_queue.get()
			self.msg_queue.task_done()
			
			# check if the packet data is in the deque
			# It does not pass it to the user if it has been already seen.
			tmp_list = list(self.msg_deque)
			for message in tmp_list:
				if message[0] == data:
					if DEBUG:
						print "Already seen message, not sending to user"
					continue
			break	
		#if DEBUG:
		#	print "Queue size: " + str(self.msg_queue.qsize())
		
		return self.cryptor.decrypt(data)
		
	
class BunnyReadThread(threading.Thread):

	def __init__(self, queue, out_queue, ioObj, model):
		self.msg_queue = queue
		self.out_queue = out_queue
		self.inandout = ioObj
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
						if DEBUG:
							print "Adding message to Queue"
						self.msg_queue.put(decoded)
						
						self.out_queue.put(decoded)
						#TIMING
						#print "recv time: %f" % (time.time() - start_t)
						
						# clean up for the next loop
						blockget = False
						decoded = ""
						
class BroadCaster(threading.Thread):
	
	def __init__(self, queue, deque, ioObj, model):
		self.out_queue = queue
		self.msg_deque = deque
		self.inandout = ioObj
		self.model = model
		
		self.seen_chunks = []
		
		threading.Thread.__init__(self)
	
	def run(self):
		while True:
			packet = self.out_queue.get()
			self.out_queue.task_done()
			
			# check if the packet data is in the deque
			tmp_list = list(self.msg_deque)
			for message in tmp_list:
				if message[0] == packet:
					if DEBUG:
						print "Already seen message, not relaying"
					return
				# check if any of the messages in the deque need to be removed due to time
				# 	current the time for no relay is 1 min
				if time.time() - message[1] > 60:
					self.msg_deque.remove(message)
			
			# if we did not return then we add the current message to the deque and 
			# start bunny-ifcation
			self.msg_deque.append([packet, time.time()])
				
			#TIMING
			#start_t = time.time()
			if DEBUG:
				print "CypherText: " + binascii.hexlify(packet)
				print "blocks: " + binascii.hexlify(packet[16:18])
			
			
			while ( len(packet) != 0 ):
				entry = self.model.getEntryFrom(self.model.type_ranges)
				try:
					outpacket = entry[2].makePacket(packet[:entry[3]])
					if DEBUG:
						print "Sending with: %s" % self.model.rawToType(entry[0])
						print "length: " + str(len(outpacket))
					
				except AttributeError:
					#TODO:?
					# WTF does this do?
					continue
				packet = packet[entry[3]:]
				self.inandout.sendPacket(outpacket)
			#TIMING
			#print "Send time: " + str(time.time() - start_t)
	
