

from datetime import datetime
import socket
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from datetime import datetime
from scapy.all import *


def check_host(ip, timeout=1):
	conf.verb = 0
	try:
		ping = sr1(IP(dst=ip)/ICMP(), timeout=timeout)
		print(ip, " is up, Beginning Scan")
		return True
	except Exception:
		print("Couldn't resolve ", ip)
		return False

def probe_port(target, port, timeout=1):
	src_port = RandShort()
	try:
		p = IP(dst=target)/TCP(sport=src_port, dport=port, flags='S')
		resp = sr1(p, timeout=timeout) 
		if resp == None:
			return False
		elif resp.haslayer(TCP):
			if resp.getlayer(TCP).flags == 0x14:
				return False #Check this flag 
			if resp.getlayer(TCP).flags == 0x12:
				sr(IP(dst=target)/TCP(sport=src_port, dport=port, flags='AR'), timeout=timeout)
				return True
	except Exception as e:
		pass

def stealthportscan(target, min_port=0, max_port=100, timeout=1):

	target = socket.gethostbyname(target)
	print("Target : ", target)
	if (int(min_port) >= 0 and int(max_port) >=0 and int(max_port) >= int(min_port)):
		ports = range(int(min_port), int(max_port)+1)
		start_clock = datetime.now()
		open_ports = 0
		print("Stealth Scan started at ", start_clock)
		if (check_host(target, timeout) == True):
			for port in ports:
				status = probe_port(target, port, timeout)
				if (status == True):
					open_ports += 1
					print("Target : ", target, " Port : ", port, " Open!")
			stop_clock = datetime.now()
			total_time = stop_clock - start_clock
			print("Stealth Scan Finished\n", open_ports, "Ports Open on", int(max_port) - int(min_port))
			print("Scan Duration : ", total_time)


if __name__ == '__main__':
	match len(sys.argv):
		case 1:
			stealthportscan("127.0.0.1")
		case 2:
			stealthportscan(sys.argv[1])
		case 4:
			stealthportscan(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
		case 5:
			stealthportscan(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]))



