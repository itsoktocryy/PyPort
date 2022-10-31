from datetime import datetime
import socket
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from datetime import datetime
from scapy.all import *

# dst_ip = “10.0.0.1”
# src_port = RandShort()
# dst_port=53
# dst_timeout=10

def check_host(ip, timeout=1):
	conf.verb = 0
	try:
		ping = sr1(IP(dst=ip)/UDP(), timeout=timeout)
		print(ip, " is up, Beginning Scan")
		return True
	except Exception:
		print("Couldn't resolve ", ip)
		return False

def probe_port(target, port, timeout=1):
	src_port = RandShort()
	try:
		p = IP(dst=target)/UDP(sport=src_port, dport=port, flags='S')
		resp = sr1(p, timeout=timeout) 
		if resp == None:
			return False
		elif resp.haslayer(UDP):
			if(int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code)==3):
				return False #Check this flag 
			if resp.getlayer(UDP).flags == 0x12:
				sr(IP(dst=target)/UDP(sport=src_port, dport=port, flags='AR'), timeout=timeout)
				return True
	except Exception as e:
		pass

def udpscan(ip, min_port, max_port, timeout=1):
    target = socket.gethostbyname(target)
    print("Target : ", target)
    if (int(min_port) >= 0 and int(max_port) >=0 and int(max_port) >= int(min_port)):
        ports = range(int(min_port), int(max_port)+1)
        start_clock = datetime.now()
        print("Stealth Scan started at ", start_clock)
        if (check_host(target, timeout)):
            for port in ports:
                status = probe_port(target, port, timeout)
                if (status == True):
                    print("Target : ", target, " Port : ", port, " Open!")
                    stop_clock = datetime.now()
                    total_time = stop_clock - start_clock
                    print("UDP Scan Finished")
                    print("Scan Duration : ", total_time)


if __name__ == '__main__':
	timeout=0.5
	if (len(sys.argv) == 5):
		timeout = int(sys.argv[4])
	udpscan(sys.argv[1],int(sys.argv[2]), int(sys.argv[3]), timeout)


    # for count in range(0,3):
    #     retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout))
    #     for item in retrans:
    #         if (str(type(item))!=”<type 'NoneType'>”):
    #     udp_scan(dst_ip,dst_port,dst_timeout)
    #     return "Open|Filtered"      
    # elif (udp_scan_resp.haslayer(UDP)):
    #     return "Open"
    # elif(udp_scan_resp.haslayer(ICMP)):
    #     if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
    #         return "Closed"
    # elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
    #     return "Filtered"