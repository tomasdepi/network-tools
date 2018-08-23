import sys
import optparse
import scapy.all as scapy

parser = optparse.OptionParser()
parser.add_option("-r", "--range", dest="range")

(options, arguments) = parser.parse_args()

if not options.range:
	print("[-] Usage: python scan_network.py -r 192.168.1.10/24")
	sys.exit(1)

def scan_network(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request

	answered_packets = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] #timeout in seconds

	print("IP\t\t\tMAC Address\n------------------------------------------")

	for packet in answered_packets:
		print(packet[1].psrc + "\t\t" + packet[1].hwsrc)


scan_network(str(options.range))