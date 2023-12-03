import time
import multiprocessing as mp
from scapy.all import IP, TCP, send
import queue
import os
import signal


def extract(cw, loss_turn, inflate_turn):


    # if len(cw) < 15:
    # 	return None
    # index = 3
    # while (cw[index] != 1):
    # 	index =index + 1
    # loss_rtt = index-1
    # if cw[loss_rtt-1] > 128:
    # 	loss_cw = cw[index-1]+cw[index-2]-128
    # else:
    # 	loss_cw = cw[index-1]

    # index = index + 1
    # while (cw[index+1] > 1.9 * cw[index] and cw[index+1] < 2.1*cw[index]):
    # 	index = index + 1
    # sst = cw[index+1]
    # sst_rtt = index + 1

    loss_rtt = loss_turn
    loss_cw = cw[loss_turn]

    sst_rtt = inflate_turn
    sst = cw[inflate_turn]


    return [sst/(loss_cw+0.0),
            cw[loss_rtt+2]-cw[loss_rtt+1], cw[loss_rtt+3]-cw[loss_rtt+1], cw[loss_rtt+4]-cw[loss_rtt+1],
            cw[sst_rtt+1]- cw[sst_rtt], cw[sst_rtt+3]- cw[sst_rtt], cw[sst_rtt+5]- cw[sst_rtt], cw[sst_rtt+7]- cw[sst_rtt]]

def my_extract(drop_turn, inflate_turn, cwnds):
    print(drop_turn, inflate_turn)
    phase1_init_cwnd = cwnds[0]
    phase2_init_cwnd = cwnds[drop_turn + 3]
    phase3_init_cwnd = cwnds[inflate_turn +3]

    p1_offsets = [i - phase1_init_cwnd for i in cwnds[0:drop_turn + 3]]
    print(p1_offsets)
    p2_offsets = [i-phase2_init_cwnd for i in cwnds[drop_turn + 3: inflate_turn + 3]]
    print(p2_offsets)
    p3_offsets = [i-phase3_init_cwnd for i in cwnds[inflate_turn+3:]]
    print(p3_offsets)
    return (sum(p1_offsets), sum(p2_offsets), sum(p3_offsets))

# TODO:
# Measure RTT?
# Try to make the vector
# Plot graphs for each algorithm
# try running tcpprob/ftrace on azure machine

# Issues
# bbr - we reach steady state ~15 packets/RTT way before reaching LOSS_CW
# vegas staeady state ~60
DROP_TURN = 14

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

def q_listen(pkt_q, rtt, request_pkt):
    time.sleep(rtt)
    send(request_pkt)

    max_seq_seen = 0
    cwnds = [1, 1]
    turn = 0
    max_ack = 0
    has_dropped = False
    LATEST_DROP = 21
    INFLATE_TURN = 100000000
    STOP_TURN = 100000000

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
            pkt = make_ack_for_pkt(pkt, max_ack)
        
            if pkt is not None:
                (ack, max_ack) = pkt
                acks.append(ack)

        # Drop some packet
        if (this_cwnd >= LOSS_CW  or turn == LATEST_DROP) and not has_dropped:
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
            INFLATE_TURN = turn + 7
            STOP_TURN = INFLATE_TURN + 7

        # Window Emptying
        if len(acks) > 0: send(acks) 

        if turn >= INFLATE_TURN: rtt += INFLATE_BY
        print("This window: ", this_cwnd, turn, INFLATE_TURN, STOP_TURN)
        cwnds.append(this_cwnd)
        turn += 1
    print(",".join([str(i) for i in cwnds]))
    print(my_extract(INFLATE_TURN - 7, INFLATE_TURN, cwnds))
    print(extract(cwnds, INFLATE_TURN - 7, INFLATE_TURN))

    ppid = os.getppid()
    os.kill(ppid, signal.SIGKILL)
    




