#!/usr/bin/env python
import sys
import getopt
import pylorcon

try:
	lorcon = pylorcon.Lorcon("wlan1", "rtl8187")
except pylorcon.LorconError:
	print "Please run me as root"
	
lorcon.setfunctionalmode("INJECT");
lorcon.setmode("MONITOR");
lorcon.setchannel(6);

packet = "AAAAAAAAA"
lorcon.txpacket(pack);
