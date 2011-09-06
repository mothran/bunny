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
import sys
import pylorcon
import time
from pcapy import open_live

class Bunny():
	def send(self, data, num):
		for n in range(num):
			self.lorcon.txpacket(data)
	
	
	def recive(self):
		header, rawPack = self.pcapy.next()
		
	
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
	
	def start(self, iface, driver, chan):
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

# end of Bunny class

bunny = Bunny()
bunny.start("wlan1", "rtl8187", 6)
#bunny.send("AAAAAHELLOAAAAA", 2000)
bunny.reloop()

print "Done"
