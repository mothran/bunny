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

import struct, os, time, pipes

import pylorcon
from pcapy import open_live

from config import *


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
		
		self.lorcon.setfunctionalmode("INJMON")
		self.lorcon.setchannel(CHANNEL)
		
		# This needs an audit.
		os.system("ifconfig " + pipes.quote(IFACE) + " up")
		
		# Quick definitions for pcapy
		MAX_LEN      = 1514		# max size of packet to capture
		PROMISCUOUS  = 1		# promiscuous mode?
		READ_TIMEOUT = 0		# in milliseconds
		MAX_PKTS     = 1		# number of packets to capture; 0 => no limit
		
		try:
			self.pcapy = open_live(IFACE, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
		except PcapError as err:
			print "Error creating pcapy descriptor, try turning on the target interface or setting it to monitor mode"
			print str(err)
		
	def updateChan(self, channel):
		"""
		
		Updates the current channel
		
		"""
		self.lorcon.setchannel(channel)
	
	# These send/rec functions should be used in hidden / paranoid mode.
	def sendPacket(self, data):
		if data is not None:
			try:
				self.lorcon.txpacket(data)
			except pylorcon.LorconError as err:
				print "ERROR sending packet: "
				print str(err)
	def recPacket_timeout(self, fcs):
		"""
		return the raw packet if the mod/remain value is correct. 
		returns False upon a timeout
		
		"""
		start_t = time.time()
		while(time.time() - start_t < TIMEOUT):
			header, rawPack = self.pcapy.next()
			if rawPack is None:
				continue
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
			return False
	
	def reloop(self):
		"""
		This exists only for testing purposes.
		Too ensure proper packets are read properly and at a high enough rate. 
		"""
		count = 0
		packNum = 200
		startTime = time.time()
		for n in range(packNum):
			header, rawPack = self.pcapy.next()
			if rawPack is None:
				continue
			# H = unsigned short
			size = struct.unpack("<H", rawPack[2:4])
			size = int(size[0])
			
			# check if the radio tap header is from the interface face itself (loop backs)
			#  that '18' might need to change with different hardware and software drivers
			if size >= 18:
				rawPack = rawPack[size:]
				size = len(rawPack)
				# subtract the FCS to account for the radiotap header adding a CRC32
				if (round( (size - 4) % MODULUS, 2) == REMAINDER):
					print "pack num: %d, " % n  
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
