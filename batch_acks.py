import time
import multiprocessing as mp
from scapy.all import IP, TCP, send

# TODO:
# Measure RTT?
# Try to make the vector

# DONE:
# Batch acks-
# Sequence check

def make_ack_for_pkt(pkt):
    pkt_payload_len = len(bytes(pkt[TCP].payload))
    if pkt_payload_len == 0: return None
    ack_pkt = IP(dst=pkt[IP].src) / TCP(dport=80, sport=pkt[TCP].dport,
                 seq=pkt[TCP].ack, ack=pkt[TCP].seq + pkt_payload_len + 1, flags='A')
    return ack_pkt

def q_listen(pkt_q, rtt):
    #max_seq_seen = 0
    cwnds = [1, 1]
    
    while True:
        time.sleep(rtt)
        print("======== Begin RTT===========")
        acks_to_send = pkt_q.qsize()
        seen_seqs = set()
        this_cwnd =  0
        acks = []

        for pkt_num in range(acks_to_send):

            pkt = pkt_q.get_nowait()
            
            # Sequence check
            if pkt[TCP].seq not in seen_seqs:
                this_cwnd += 1
                seen_seqs.add(pkt[TCP].seq)
            
            if "F" in pkt[TCP].flags:
                pkt_payload_len = len(bytes(pkt[TCP].payload))
                fin_ack_pkt = IP(dst=pkt[IP].src) / TCP(dport=80, sport=pkt[TCP].dport,
                                 seq=pkt[TCP].ack, ack=pkt[TCP].seq + pkt_payload_len + 1, flags='FA')
                acks.append(fin_ack_pkt)
                print("Sent finack")
                pkt_q.close()
                send(acks)
                return
            
            ack = make_ack_for_pkt(pkt)
            if ack is not None: acks.append(ack)
        
        # Window Emptying
        if len(acks) > 0: send(acks)
        print("This window: ", this_cwnd)
        cwnds.append(this_cwnd)



