import sys
import optparse
from utilities import change_mac

parser = optparse.OptionParser()
parser.add_option("-i", "--interface", dest="interface", help="Network Interface")
parser.add_option("-m", "--mac", dest="new_mac", help="New mac to Spoof")

(options, arguments) = parser.parse_args()

if not options.interface or not options.new_mac:
	print("[-] Usage: python mac_changer.py -i [interface] - m [new_mac]")
	sys.exit(1)

interface = options.interface
new_mac = options.new_mac

if __name__ == '__main__':
	change_mac(interface, new_mac)