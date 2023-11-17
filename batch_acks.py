import time
import multiprocessing as mp
from scapy.all import IP, TCP, send
import queue

# TODO:
# Measure RTT?
# Try to make the vector

# DONE:
# Batch acks-
# Sequence check

DROP_TURN = 14
INFLATE_TURN = 21
STOP_TURN = 30
INFLATE_BY = 0.05
LOSS_CW = 128

def make_ack_for_pkt(pkt, max_ack):
    pkt_payload_len = len(bytes(pkt[TCP].payload))
    #print("len ", pkt_payload_len, len(pkt[TCP].payload))
    if pkt_payload_len == 0: return None
    max_ack = max(max_ack, pkt[TCP].seq + pkt_payload_len)
    ack_pkt = IP(dst=pkt[IP].src) / TCP(dport=80, sport=pkt[TCP].dport,
                 seq=pkt[TCP].ack, ack=max_ack, flags='A')
    return (ack_pkt, max_ack)

def q_listen(pkt_q, rtt):
    max_seq_seen = 0
    cwnds = [1, 1]
    turn = 0
    max_ack = 0
    has_dropped = False

    while turn < STOP_TURN:
        time.sleep(rtt)
        max_ack_turn_start = max_ack
        print("======== Begin RTT===========")
        pkts = []
        acks_to_send = 0
        try:
            while True:
                pkts.append(pkt_q.get_nowait())
                acks_to_send += 1
        except queue.Empty:
            pass


        seen_seqs = set()
        this_cwnd =  0
        this_cwnd_test = 0
        acks = []

        for pkt_num in range(acks_to_send):

            pkt = pkts[pkt_num]
            # Sequence check
            if pkt[TCP].seq not in seen_seqs:
                this_cwnd_test += 1
                seen_seqs.add(pkt[TCP].seq)
            
            if pkt[TCP].seq + len(bytes(pkt[TCP].payload)) > max_seq_seen:
                this_cwnd += 1
                max_seq_seen = pkt[TCP].seq + len(bytes(pkt[TCP].payload)) 
            
            if "F" in pkt[TCP].flags:
                pkt_payload_len = len(bytes(pkt[TCP].payload))
                fin_ack_pkt = IP(dst=pkt[IP].src) / TCP(dport=80, sport=pkt[TCP].dport,
                                 seq=pkt[TCP].ack, ack=pkt[TCP].seq + pkt_payload_len + 1, flags='FA')
                acks.append(fin_ack_pkt)
                print("Sent finack")
                pkt_q.close()
                send(acks)
                return
            #print("seq", pkt[TCP].seq)
            (ack, max_ack) = make_ack_for_pkt(pkt, max_ack)

            # if dropped_ack is not None:
            #     if pkt[TCP].seq + len(bytes(pkt[TCP].payload))+ 1 == dropped_ack:
            #         dropped_ack = None
            #     else:
            #         ack[TCP].ack = dropped_ack

            if ack is not None: acks.append(ack)

        # Drop some packet
        if this_cwnd >= LOSS_CW and not has_dropped:
            # dropped_ack_pkt = acks[-1]
            # dropped_ack = dropped_ack_pkt[TCP].ack
            # acks = acks[:-1]

            # assert(len(acks) >= 4)
            # acks[-1] = acks[-4]
            # acks[-2] = acks[-4]
            # acks[-3] = acks[-4]
            # acks = acks[:-1]
            # max_ack = acks[-1][TCP].ack
            # print("Triple DUP ack...")

            acks = []
            max_ack = max_ack_turn_start
            has_dropped = True

        # Window Emptying
        if len(acks) > 0: send(acks) 

        if turn >= INFLATE_TURN: rtt += INFLATE_BY
        print("This window: ", this_cwnd, this_cwnd_test, max_ack, turn)
        cwnds.append(this_cwnd)
        turn += 1
    print(cwnds)


