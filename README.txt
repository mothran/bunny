# depends:
  -pycrypto
  -lorcon
  -pylorcon
  -pcapy

For full whitepaper like decription of Bunny check proposal.txt.
For installation help check INTALL file.

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

TODO:

 Implement pylorcon2 and lorcon2 once more drivers are added in lorcon2

 Improve the chat client interface with a simple curses chat window thing

 Routing layers and support for projects to be built ontop of what I have done
like cjdns and others
