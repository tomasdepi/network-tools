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