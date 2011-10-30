#!/usr/bin/env python
import sys
import getopt
import pylorcon

def send(pack):
	try:
		lorcon = pylorcon.Lorcon("wlan1", "rtl8187")
	except pylorcon.LorconError:
		print "Please run me as root"
		
	lorcon.setfunctionalmode("INJECT");
	lorcon.setmode("MONITOR");
	lorcon.setchannel(6);
	
	for n in range(255):
		lorcon.txpacket(pack);
	print "Done";

packet = "AAAAAAAAA"
options, remainder = getopt.getopt(sys.argv[1:], "srd:")
for opt, arg in options:
	if opt in ("-s"):
		send(packet)
	elif opt in ("-r"):
		print "you selected -r!"
	else:
		print "Meh"
