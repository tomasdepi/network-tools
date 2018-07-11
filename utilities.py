import subprocess

def change_mac(interface, mac):
	subprocess.call(["ifconfig", interface, "down"])
	subprocess.call(["ifconfig", interface, "hw", "ether", mac])
	subprocess.call(["ifconfig", interface, "up"])