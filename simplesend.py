#!/usr/bin/env python
import pylorcon

try:
	lorcon = pylorcon.Lorcon("wlan1", "rtl8187")
except pylorcon.LorconError:
	print "PLease run me as root"
	
lorcon.setfunctionalmode("INJECT");
lorcon.setmode("MONITOR");
lorcon.setchannel(6);

pack = "AAAAAAAAA"
for n in range(255):
	lorcon.txpacket(pack);
print "Done";
