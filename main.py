import random
import sys

import getopt
import socket
from scapy.all import IP, TCP, sr1, sniff

import batch_acks
import multiprocessing as mp

# DTW on raw time series

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


	RTT = 0.8
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

	dst_port = 80
	dst_name = url

	seq = random.randrange(100000,99999999)
	src_port = random.randrange(20000,50000)

	syn = IP(dst=dst_ip) / TCP(dport=80, sport=src_port, seq=seq, flags='S',
							   options=[("MSS",MSS), ("NOP",None),('WScale', 10)])
	syn_ack = sr1(syn)
	print(syn_ack)
	print(syn_ack[IP].src)
	getStr = f'GET {req_obj} HTTP/1.1\r\nHost: {url}\r\nConnection: Close\r\n\r\n'
	request = IP(dst=f'{url}') / TCP(dport=80, sport=syn_ack[TCP].dport,
				seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A') / getStr
	

	pkt_q = mp.Queue()
	batch_proc = mp.Process(target=batch_acks.q_listen, args=(pkt_q, RTT, request, fname))
	batch_proc.start()
	packets = sniff(prn=lambda pkt: pkt_q.put_nowait(pkt),filter=f"src host {syn_ack[IP].src}")
	batch_proc.join()