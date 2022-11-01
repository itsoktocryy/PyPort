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


def probe_port(target, timeout=3):
    try:
        p = IP(dst=target)/ICMP()
        resp = sr1(p, timeout=timeout)
        if resp:
            if IP in resp:
                ttl = resp.getlayer(IP).ttl
                if ttl == 32:
                    os = "Prolly some ol' Windows"
                elif ttl <= 64:
                    os = "*nix distribution"
                elif ttl > 64:
                    os = "Windows distribution"
                elif ttl == 254:
                    os = "Solaris distribution"
                elif ttl == 255:
                    os = "Multiple possibilities found"
                return(os)
        elif resp == None:
            return False    
    except Exception as e:
        pass

def osdetection(target, min_port=0, max_port=100, timeout=1):
    print(probe_port(target, 3))

if __name__ == '__main__':
	match len(sys.argv):
		case 1: #Scan localhost
			osdetection("IPaddr")
		case 2: #Scan custom IP (Default port from 0 to 100, default timeout = 1sec)
			osdetection(sys.argv[1])
		case 4: #Scan custom IP and set min_port and max_port
			osdetection(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
		case 5: #Scan custom IP and set min_port , max_port and timeout
			osdetection(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]))
