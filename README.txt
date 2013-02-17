# depends:
  -pycrypto
  -lorcon
  -pylorcon
  -pcapy

For full whitepaper like decription of Bunny check proposal.txt.
For installation help check INSTALL file.

Currently implemented:
 -Traffic modeling with
  *AP and client lists
  *Packet types and distribution

 -Packet creation with packet type implemented:
  *Beacons
  *Probe Requests
  *DataQOS

 Userlayer:
 -Chatclient with usernames

Using libbunny:

example:
	import libbunny
	
	bunny = libbunny.Bunny()
	bunny.sendBunny(DATA)

	while True:
		try:
			print bunny.recvBunny()
		except libbunny.TimeoutWarning
			pass

Configuring bunny is as simple as editing the config.py


TODO:

 Programatically change config data.

 Implement pylorcon2 and lorcon2 once more drivers are added in lorcon2

 Routing layers and support for projects to be built ontop of what I have done
like cjdns and others
