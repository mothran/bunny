#!/usr/bin/env python
import sys
import pylorcon

try:
	lorcon = pylorcon.Lorcon("wlan2", "rtl8187")
except pylorcon.LorconError:
	print "Please run me as root"
	
lorcon.setfunctionalmode("INJECT");
lorcon.setmode("MONITOR");
lorcon.setchannel(9);

packet = "A" * 1400
for a in range(1, 200):
	lorcon.txpacket(packet);
