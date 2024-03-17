import random
import sys
from time import sleep

import getopt
import socket
from scapy.all import *

import batch_acks
import multiprocessing as mp

# DTW on raw time series
def start_tcpdump(interface, trace_name, host):
    p = subprocess.Popen(["tcpdump", "-i", interface, "port", "80", "or", "port", "443", "and", "host", host, "-w", trace_name])
    return p

if __name__ == "__main__":
	
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hi:u:o:f:t:")
	except getopt.GetoptError:
		print("Input Error")
		sys.exit(2)

	for cmd, arg in opts:
		if cmd in ("-h"):
			print("help info")
			sys.exit()
		elif cmd in ("-o"):
			output = arg
		elif cmd in ("-i"):
			interface = arg
		elif cmd in ("-u"):
			url = arg
		elif cmd in ("-f"):
			fname = arg

	if interface == '':
		print("Please input network interface")
		sys.exit(2)


	RTT = 0.6
	MSS = 200
	LOSS_CW = 128

	url='74.235.199.17'
	dst_ip = socket.gethostbyname(url)
	site_obj = f"http://{url}/testfiles/100MBfile.txt"

	site_obj = site_obj[7:]
	if site_obj.find("/") != -1:
		# exist large ojb
		str_list = site_obj.split('/', 1)
		site_url = str_list[0]
		req_obj = '/'+str_list[1]
	else:
		site_url = site_obj
		req_obj = '/'

	# server = "128.105.145.220"
	# reqstr = f"GET /testfiles/100MBfile.txt HTTP/1.1\r\nHost: 128.105.145.220\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36\r\nConnection: Close\r\n\r\n"
	server = "146.75.29.164"
	reqstr = f"GET / HTTP/1.1\r\nHost: cooking.nytimes.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36\r\nConnection: Close\r\n\r\n"

	start_tcpdump("wlo1", "test-tls.pcap", server)

	load_layer("tls")
	subprocess.run(f"tc qdisc del dev {interface} root".split(" "))	
	sleep(1)
	subprocess.run(f"sudo tc qdisc add dev {interface} root netem slot 700ms".split(" "))
	sleep(1)

	pkt_q = mp.Queue()
	sniff_proc = mp.Process(target=sniff, kwargs = {"prn": lambda pkt: pkt_q.put_nowait(pkt), "filter": f"src host {server}"})
	sniff_proc.start()

	conn = TLSClientAutomaton.tlslink(Raw, server=server, dport=443)
	# print(conn.atmt.__dir__())
	while not conn.atmt.__IG_HANDSHAKE_DONE__: pass
	
	local_port = conn.atmt.__IG_PORT_NUMBER__

	try: 
		while True: print(pkt_q.get_nowait())
	except queue.Empty:
		print("empty")
		pass

	conn.send(Raw(reqstr))

	# while not conn.atmt.__IG_SETUP_DONE__: pass
	print("setup done!")
	subprocess.run(f"tc qdisc del dev {interface} root".split(" "))	
	batch_acks.q_listen(pkt_q, local_port, RTT, fname)