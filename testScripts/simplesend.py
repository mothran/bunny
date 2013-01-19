#!/usr/bin/env python
import sys
import getopt
import pylorcon

import ConfigParser


config = ConfigParser.RawConfigParser()
config.add_section("LORCON")
config.set("LORCON", "chan", 6)
with open("test.conf", "wb") as configfile:
	config.write(configfile)

try:
	lorcon = pylorcon.Lorcon("wlan1", "rtl8187")
except pylorcon.LorconError:
	print "Please run me as root"
	
lorcon.setfunctionalmode("INJECT");
lorcon.setmode("MONITOR");
lorcon.setchannel(6);

packet = "A" * 1400
for a in range(1, 200):
	lorcon.txpacket(packet);
