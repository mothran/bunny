#Bunny
Bunny is intended to act as a layer 1/2 technology that attempts to hide its wireless mesh communication traffic.
Bunny wraps all data in and out in a layer of obfoscation, it does this by passively listening to 
the local wireless and building a model of 'average' traffic. Then using this model it hides small 
snippets of data within various fields of the 802.11 protocol, that are either poorly defined or 
prone to contain data that mutates a lot.  These fields will include but are not limited to; vendor 
data, data packets of encrypted networks, duration fields.


For full whitepaper like decription of Bunny check proposal.txt.


You need a monitor/injection capable wireless chipset.  Please check the aircrack website for 
compatible cards.


##Tested cards / chipsets:
	rtl8187		-	Alfa AWUS036NH
	ath9k_htc	-	TP-LINK
	rt2800usb	-	

##Usage (bunnyChat.py example code)

	sudo python bunnyChat.py
	
	-l              --   Listen mode, gets packets and prints data
	-s [data]       --   Send mode, sends packets over and over
	-m              --   Passive profiling of all the channels (1-11)
	-c [UserName]   --   Chat client mode
	-r              --   Reloop shows the mod/remainder of the specified channel
	-p              --   Ping/Pong testing, Run this on one machine and it will
						 respond with a pong.
	-k              --   Ping server mode, will repsond to pings with pong and current time

##Usage of the module
	import libbunny
	
	bunny = libbunny.Bunny()
	bunny.sendBunny(DATA)

	while True:
		print bunny.recvBunny()

Configuring bunny is as simple as editing the libbunny/config.py

##Dependencies

	pycrypto
	lorcon
	pylorcon
	pcapy

##Installation
Check INSTALL file

##TODO

Implement pylorcon2 and lorcon2 once more drivers are added in lorcon2

Routing layers and support for projects to be built ontop of what I have done
like cjdns and others

Attempt to make a bunny tun device so testing with the batman-adv kernal module.
