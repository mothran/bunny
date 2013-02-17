import pylorcon

cards = pylorcon.getcardlist()

# ebay search string:
#	Without Alpha:
# 	("AWLL3026", "NT-WGHU", "WUSB54GC", Netgear WG111, "Asus WL-167g v2", "Digitus DN-7003GS", "D-Link DWL-G122", "D-Link WUA-1340", "Hawking HWUG1", "Linksys WUSB54G v4")
#
#	With Alpha:
#	("Alfa AWUS036E", "Alfa AWUS036H", "Alfa AWUS036S", "Alfa AWUS050NH", "Asus WL-167g v2", "Digitus DN-7003GS", "D-Link DWL-G122", "D-Link WUA-1340", "Hawking HWUG1", "Linksys WUSB54G v4")
#
# always cross ref with: http://www.aircrack-ng.org/doku.php?id=compatibility_drivers

for card in cards:
	print card['name']

