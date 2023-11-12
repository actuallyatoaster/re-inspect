import time
import multiprocessing as mp
from scapy.all import IP, TCP, send

# TODO:
# Measure RTT?
# Sequence check
# Try to make the vector

# DONE:
# Batch acks

def make_ack_for_pkt(pkt):
    pkt_payload_len = len(bytes(pkt[TCP].payload))
    if pkt_payload_len == 0: return
    ack_pkt = IP(dst=pkt[IP].src) / TCP(dport=80, sport=pkt[TCP].dport,
                 seq=pkt[TCP].ack, ack=pkt[TCP].seq + pkt_payload_len + 1, flags='A')
    return ack_pkt

def q_listen(pkt_q, rtt):
    while True:
        time.sleep(rtt)
        print("======== Begin RTT===========")
        acks_to_send = pkt_q.qsize()
        acks = []
        for pkt_num in range(acks_to_send):
            pkt = pkt_q.get_nowait()
            # print(pkt.summary())
            # print(bytes(pkt[TCP].payload))
            
            if "F" in pkt[TCP].flags:
                pkt_payload_len = len(bytes(pkt[TCP].payload))
                fin_ack_pkt = IP(dst=pkt[IP].src) / TCP(dport=80, sport=pkt[TCP].dport,
                                 seq=pkt[TCP].ack, ack=pkt[TCP].seq + pkt_payload_len + 1, flags='FA')
                acks.append(fin_ack_pkt)
                print("Sent finack")
                pkt_q.close()
                send(acks)
                return
            #print(bytes(pkt[TCP].payload))
            acks.append(make_ack_for_pkt(pkt))
        send(acks)



