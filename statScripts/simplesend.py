#!/usr/bin/env python
import sys
import pylorcon
import time

try:
	lorcon = pylorcon.Lorcon("wlan4", "ath9k_htc")
except pylorcon.LorconError:
	print "Please run me as root"
	
lorcon.setfunctionalmode("INJECT");
lorcon.setmode("MONITOR");
lorcon.setchannel(9);

packet = "\x2b" * 140
for a in range(0, 30):
	lorcon.txpacket(packet);
	time.sleep(0.04)
