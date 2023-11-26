# -*- coding: utf-8 -*
from __future__ import with_statement
from __future__ import print_function
import sys
# sys.path.append('/home/Documents/IG/lib/python2.7/site-packages')
#sys.path.append('/home/neko/Projects/re-inspect/src/lib/python2.7/site-packages')
from socket import socket, AF_PACKET, SOCK_RAW, htons
from struct import *
import select
import time
import random
import http as HTTP
from queue import Queue
import threading
import csv
import string
import os
import getopt
from bs4 import BeautifulSoup
import requests
import socket
from scapy.all import *
#from scapy_ssl_tls.ssl_tls import *
#from sklearn.externals import joblib

import batch_acks
import multiprocessing as mp

class TcpHandshake(object):
	def __init__(self, target, mss):
		self.seq = random.randrange(100000,99999999)
		self.dst_ip = target[0]
		self.dst_port = target[1]
		self.src_port = random.randrange(20000,50000)
		self.custom_options = [("MSS",mss), ("NOP",None),('WScale', 10)]
		self.pkt = IP(dst=self.dst_ip)/TCP(sport=self.src_port, dport=self.dst_port, window=65535, flags=0, seq=self.seq, options=self.custom_options)
		self.src_ip = self.pkt.src
		self.swin = self.pkt[TCP].window
		self.dwin=1
	
	def send_syn1(self):
		self.pkt[TCP].flags = "S"
		try:
			res_pkt = sr1(self.pkt, timeout=5)
		except Exception as e:
			return None
		return res_pkt

	def send_synack_ack(self, temp_pkt):
		time.sleep(0.6)
		self.pkt[TCP].flags = "A"
		self.pkt[TCP].ack = temp_pkt[TCP].seq + 1
		self.pkt[TCP].seq = temp_pkt[TCP].ack
		send(self.pkt) # no response for ack

# def extract(cw):
# 	loss_cw = 0
# 	loss_rtt = 0
# 	sst = 0
# 	sst_rtt = 0

# 	if len(cw) < 15:
# 		return None
# 	index = 3
# 	while (cw[index] != 1):
# 		index =index + 1
# 	loss_rtt = index-1
# 	if cw[loss_rtt-1] > 128:
# 		loss_cw = cw[index-1]+cw[index-2]-128
# 	else:
# 		loss_cw = cw[index-1]

# 	index = index + 1
# 	while (cw[index+1] > 1.9 * cw[index] and cw[index+1] < 2.1*cw[index]):
# 		index = index + 1
# 	sst = cw[index+1]
# 	sst_rtt = index + 1

# 	return [sst/(loss_cw+0.0),
# 			cw[loss_rtt+2]-cw[loss_rtt+1], cw[loss_rtt+3]-cw[loss_rtt+1], cw[loss_rtt+4]-cw[loss_rtt+1],
# 			cw[sst_rtt+1]- cw[sst_rtt], cw[sst_rtt+3]- cw[sst_rtt], cw[sst_rtt+5]- cw[sst_rtt], cw[sst_rtt+7]- cw[sst_rtt]]




if __name__ == "__main__":

	# url = ''
	# output = ''
	# cw_trace = []

	try:
		opts, args = getopt.getopt(sys.argv[1:], "hi:u:o:")
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

	# if url == '':
	# 	print("Please input url")
	# 	sys.exit(2)
	if interface == '':
		print("Please input network interface")
		sys.exit(2)

	# curr_dir = os.getcwd()
	# if curr_dir[len(curr_dir) - 1] != '/':
	# 	curr_dir += '/'


	RTT = 0.7
	MSS = 200
	LOSS_CW = 128

	# url='http.badssl.com'
	url='20.106.168.254'
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
	batch_proc = mp.Process(target=batch_acks.q_listen, args=(pkt_q, RTT, request))
	batch_proc.start()

	packets = sniff(prn=lambda pkt: pkt_q.put_nowait(pkt),filter=f"src host {syn_ack[IP].src}")
	batch_proc.join()


	# ua_string = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36'

	# s = socket.socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
	# s.bind((interface, 0))
	# s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 12582912)
	# tcp_obj = TcpHandshake([dst_ip,dst_port], MSS)
	# res_pkt = tcp_obj.send_syn1()
	# print(res_pkt)
	# tcp_obj.pkt[TCP].options = []
	# tcp_obj.dst_ip = res_pkt[IP].src
	# tcp_obj.pkt[IP].dst = res_pkt[IP].src
	# tcp_obj.send_synack_ack(res_pkt)
	# src_ip = tcp_obj.pkt[IP].src

	# # Request string
	# data = f"GET {req_obj} HTTP/1.1\r\nHOST: {dst_name}\r\nUser-Agent: {ua_string}\r\n\r\n"
	# req_pkt = tcp_obj.pkt / data
	# req_pkt[TCP].flags = ""
	# print(req_pkt.summary())
	# print(req_pkt[TCP].__dir__())

	# print(sr1(req_pkt))

	#sniff(timeout=3).summary()

	# turn = 0
	# while (turn < 30):
	# 	print('turn:', turn)
	# 	try:
	# 		ETH_P_ALL = 3
	# 		ETH_P_IP = 0x800
	# 		print("here")
			
	# 		print("here2")
			
	# 		print("here3")
			
			
			
	# 		if ret[1] == None:
	# 			print("Cannot work for this website")
	# 		else:
				
	# 			f = open(curr_dir + 'conn-info.csv', 'w')
	# 			cw = csv.writer(f)
	# 			cw.writerow([tcp_obj.dst_ip, tcp_obj.src_port, tcp_obj.dst_port, RTT, MSS, tcp_obj.pkt[TCP].seq, tcp_obj.pkt[TCP].ack, \
	# 				LOSS_CW, 0, src_ip])

	# 			f.close()

	# 			try:
	# 				target_ip_port = (dst_ip,dst_port)
	# 				with TLSSocket(input_tcp_obj=tcp_obj, sock=s, client=True, dir=curr_dir) as tls_socket:
	# 					try:
	# 						server_hello, server_kex = tls_socket.do_handshake(tls_version, ciphers, extensions)
	# 					except TLSProtocolError as tpe:
	# 						print("Got TLS error: %s" % tpe, file=sys.stderr)

	# 					else:
	# 						if ua_string != '':
	# 							print("Getting started to transfer web")
	# 							tls_socket.do_round_trip_without_recv(TLSPlaintext(data=%(req_obj, dst_name, ua_string)))
	# 							tls_socket.do_round_trip_without_recv(TLSPlaintext(data="GET %s HTTP/1.1\r\nHOST: %s\r\nUser-Agent: %s\r\n\r\n"%(req_obj, dst_name, ua_string)))
	# 							tls_socket.do_round_trip_without_recv(TLSPlaintext(data="GET %s HTTP/1.1\r\nHOST: %s\r\nUser-Agent: %s\r\n\r\n"%(req_obj, dst_name, ua_string)))
	# 							tls_socket.do_round_trip_without_recv(TLSPlaintext(data="GET %s HTTP/1.1\r\nHOST: %s\r\nUser-Agent: %s\r\n\r\n"%(req_obj, dst_name, ua_string)))
	# 							tls_socket.do_round_trip_without_recv(TLSPlaintext(data="GET %s HTTP/1.1\r\nHOST: %s\r\nUser-Agent: %s\r\n\r\n"%(req_obj, dst_name, ua_string)))
	# 							tls_socket.do_round_trip_without_recv(TLSPlaintext(data="GET %s HTTP/1.1\r\nHOST: %s\r\nUser-Agent: %s\r\n\r\n"%(req_obj, dst_name, ua_string)))
	# 							tls_socket.do_round_trip_without_recv(TLSPlaintext(data="GET %s HTTP/1.1\r\nHOST: %s\r\nUser-Agent: %s\r\n\r\n"%(req_obj, dst_name, ua_string)))
	# 							tls_socket.do_round_trip_without_recv(TLSPlaintext(data="GET %s HTTP/1.1\r\nHOST: %s\r\nUser-Agent: %s\r\n\r\n"%(req_obj, dst_name, ua_string)))
	# 							tls_socket.do_round_trip_without_recv(TLSPlaintext(data="GET %s HTTP/1.1\r\nHOST: %s\r\nUser-Agent: %s\r\n\r\n"%(req_obj, dst_name, ua_string)))
	# 							tls_socket.do_round_trip_without_recv(TLSPlaintext(data="GET %s HTTP/1.1\r\nHOST: %s\r\nUser-Agent: %s\r\n\r\n"%(req_obj, dst_name, ua_string)))
	# 							resp = tls_socket.do_round_trip(TLSPlaintext(data="GET %s HTTP/1.1\r\nHOST: %s\r\nUser-Agent: %s\r\n\r\n"%(req_obj, dst_name, ua_string)))
	# 						print("*** Successfully got reponse from server ***")


	# 			except Exception as e:
	# 				print('Server response exception:', e)
	# 				exc_type, exc_obj, exc_tb = sys.exc_info()
	# 				fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
	# 				print(exc_type, fname, exc_tb.tb_lineno)
	# 				traceback.print_exc()
	# 				if os.path.exists("./trace.csv"):
	# 					cw_trace = []
	# 					trace = csv.reader(open("./trace.csv",'r'))
	# 					for row in trace:
	# 						cw = int(row[0])
	# 						if len(cw_trace) > 0:
	# 							if cw !=0:
	# 								if cw==1 and cw_trace[len((cw_trace))-1]==1:
	# 									pass
	# 								else:
	# 									cw_trace.append(cw)
	# 						else:
	# 							cw_trace.append(cw)
	# 					os.popen("sudo rm ./trace.csv")
	# 					os.popen("sudo rm ./conn-info.csv")
	# 					os.popen("sudo rm ./pid.csv")
	# 					break
	# 				else:
	# 					turn = turn + 1

	# 		s.close()

	# 	except Exception as e:
	# 		print('e_getting_trace:', e)

	# model = joblib.load('tree')
	# cc = {0:'BBR',1:'bic',2:'highspeed',3:'htcp',4:'illinois',5:'scalable',6:'vegas',7:'veno',8:'westwood',9:'yeah',10:'cubic',11:'reno',12:"ctcp", 13:"cdg", 14:"cubic"}
	# feature = extract(cw_trace)
	# print("cw trace is ", cw_trace)
	# print("feature is", feature)
	# if feature is not None:
	# 	result = model.predict([extract(cw_trace)])
	# 	print(result[0], type(result[0]))
	# 	result = cc[int(result[0])]
	# 	print(result)

