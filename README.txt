# depends:
  -pycrypto
  -lorcon
  -pylorcon
  -pcapy

Notes:
	Upgrade to pylorcon2 and lorcon2

	End goal is to have a single staticly linked lib written in C.

End of week goals:
 -more packet templates!
 -packet example need to be more than just the first one seen.
 -Added model info:
	*WLAN encryption (yes/no) checking
	*etc
 -Find a injection capable card
 
 BUGS:
	-malformed beacon packets at end of send loop
	-crashing on decoding durring data packets

Pie in sky goals:
 -Routing layer?
 -Second level encryption
