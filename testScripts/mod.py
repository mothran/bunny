import sys
mod = 1.23
remain = 0.82

if len(sys.argv) > 2:
	mod = float(sys.argv[1])
	remain = float(sys.argv[2])

print ("Mod:\t%f" % mod)
print ("Remain:\t%f" % remain)

for i in range(1, 400):
	if round( i % mod, 2) == remain:
		print i
