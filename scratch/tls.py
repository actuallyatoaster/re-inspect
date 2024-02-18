from scapy.all import *
from check_http import start_tcpdump
from time import sleep 

load_layer("tls")
tcpdumps = start_tcpdump("wlo1", "http_check.pcap", "128.110.219.88")

# a = TLSClientAutomaton(server="128.110.219.88", dport=443, data="GET /testfiles/100MBfile.txt HTTP/1.1\r\nHost: 128.110.219.88\r\nConnection: Close\r\n\r\n")
a = TLSClientAutomaton.tlslink(Raw, server="128.110.219.88", dport=443)

sleep(1)

a.send(Raw("GET /testfiles/100MBfile.txt HTTP/1.1\r\nHost: 128.110.219.88\r\nConnection: Close\r\n\r\n"))
sleep(1)
a.close()
sniff(prn=lambda pkt: print(pkt),filter=f"src host 128.110.219.88")
tcpdumps.kill()
