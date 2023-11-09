import time
import multiprocessing as mp
from scapy.all import IP, TCP, send


def send_ack_for_pkt(pkt):
    pkt_payload_len = len(bytes(pkt[TCP].payload))
    ack_pkt = IP(dst=pkt[IP].src) / TCP(dport=80, sport=pkt[TCP].dport,
                 seq=pkt[TCP].ack, ack=pkt[TCP].seq + pkt_payload_len + 1, flags='A')
    send(ack_pkt)

def q_listen(pkt_q, rtt):
    while True:
        time.sleep(rtt)
        print("======== Begin RTT===========")
        acks_to_send = pkt_q.qsize()

        for pkt_num in range(acks_to_send):
            pkt = pkt_q.get_nowait()
            print(pkt.summary())
            print(bytes(pkt[TCP].payload))
            
            if "F" in pkt[TCP].flags:
                pkt_q.close()
                return
            #print(bytes(pkt[TCP].payload))
            send_ack_for_pkt(pkt)




