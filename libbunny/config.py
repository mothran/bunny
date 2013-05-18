# AES key and HMAC key are set in keys.kz
# They are in keyczar keys format.  They keys from this repo are only for testing
# and new keys should be generated for a live network.  Also Modulus and Remainder 
# values should be changed as well.  For help generating mod/remain vaules check 
# testScripts/mod.py

CAPLENGTH = 3

CHANNEL = 8
IFACE = "wlan3"
DRIVER = "ath9k_htc"
MODULUS = 1.21
REMAINDER = 0.85
TIMEOUT = 1

DEBUG = True
