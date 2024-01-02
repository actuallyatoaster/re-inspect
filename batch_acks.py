import time
import multiprocessing as mp
from scapy.all import IP, TCP, send
import queue
import os
import signal

# Extract function in code published by original authors
# Kept as close as possible-- original crashed every time :/
def extract(cw, loss_turn, inflate_turn):
    cw = [1, 1] + cw
    loss_rtt = loss_turn
    loss_cw = cw[loss_turn]

    sst_rtt = inflate_turn
    sst = cw[inflate_turn]


    return [sst/(loss_cw+0.0),
            cw[loss_rtt+2]-cw[loss_rtt+1], cw[loss_rtt+3]-cw[loss_rtt+1], cw[loss_rtt+4]-cw[loss_rtt+1],
            cw[sst_rtt+1]- cw[sst_rtt], cw[sst_rtt+3]- cw[sst_rtt], cw[sst_rtt+5]- cw[sst_rtt], cw[sst_rtt+7]- cw[sst_rtt]]

# Extract function implemented as described in the original paper
def my_extract(drop_turn, inflate_turn, cwnds):
    print(drop_turn, inflate_turn)
    phase1_init_cwnd = cwnds[0]
    phase2_init_cwnd = cwnds[drop_turn + 1]
    phase3_init_cwnd = cwnds[inflate_turn + 1]

    p1_offsets = [i - phase1_init_cwnd for i in cwnds[0:drop_turn + 1]]
    print(p1_offsets)
    p2_offsets = [i-phase2_init_cwnd for i in cwnds[drop_turn + 1: inflate_turn + 1]]
    print(p2_offsets)
    p3_offsets = [i-phase3_init_cwnd for i in cwnds[inflate_turn+1:]]
    print(p3_offsets)
    return (drop_turn, inflate_turn, sum(p1_offsets), sum(p2_offsets), sum(p3_offsets))

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

def q_listen(pkt_q, rtt, request_pkt, fname):
    # We just got a SYN-ACK, wait our emulated RTT then make the request
    time.sleep(rtt)
    local_port = request_pkt[TCP].sport
    send(request_pkt)

    # Trace state setup
    max_seq_seen = 0
    # cwnds = [1, 1]
    cwnds = []
    turn = 0
    max_ack = 0
    has_dropped = False
    LATEST_DROP = 21
    INFLATE_TURN = 100000000
    STOP_TURN = 100000000

    total_packets = 0

    while turn < STOP_TURN or total_packets < 4000:
        time.sleep(rtt)
        max_ack_turn_start = max_ack
        print("======== Begin RTT===========")
        pkts = []
        acks_to_send = 0
        try:
            while True:
                next_pkt = pkt_q.get_nowait()
                if next_pkt[TCP].dport != local_port: continue
                pkts.append(next_pkt)
                acks_to_send += 1
        except queue.Empty:
            pass

        this_cwnd =  0
        acks = []

        for pkt_num in range(acks_to_send):

            pkt = pkts[pkt_num]

            # Sequence check            
            if pkt[TCP].seq + len(bytes(pkt[TCP].payload)) > max_seq_seen:
                this_cwnd += 1
                max_seq_seen = pkt[TCP].seq + len(bytes(pkt[TCP].payload)) 
            
            # This shouldn't happen if we have an appropriately-sized payload
            if "F" in pkt[TCP].flags:
                pkt_payload_len = len(bytes(pkt[TCP].payload))
                fin_ack_pkt = IP(dst=pkt[IP].src) / TCP(dport=80, sport=pkt[TCP].dport,
                                 seq=pkt[TCP].ack, ack=pkt[TCP].seq + pkt_payload_len + 1, flags='FA')
                acks.append(fin_ack_pkt)
                print("Sent finack")
                pkt_q.close()
                send(acks)
                return

            pkt = make_ack_for_pkt(pkt, max_ack)
        
            if pkt is not None:
                (ack, max_ack) = pkt
                acks.append(ack)


        total_packets += len(acks)
        # Drop some packet
        if (this_cwnd >= LOSS_CW  or turn == LATEST_DROP) and not has_dropped:

            acks = []
            #max_ack = max_ack_turn_start
            has_dropped = True
            INFLATE_TURN = turn + 8
            STOP_TURN = INFLATE_TURN + 8

        # Window Emptying
        if len(acks) > 0: send(acks) 

        if turn >= INFLATE_TURN: rtt += INFLATE_BY
        print("This window: ", this_cwnd, turn, INFLATE_TURN, STOP_TURN)
        cwnds.append(this_cwnd)
        turn += 1
    print(",".join([str(i) for i in cwnds]))

    # Construct extracted vectors and write our results
    mine = my_extract(INFLATE_TURN - 7, INFLATE_TURN, cwnds)
    print(mine)

    orig = extract(cwnds, INFLATE_TURN - 7, INFLATE_TURN)
    print(orig)

    with open(f"{fname}-orig.txt", "a") as f:
        f.write(f"{orig}\n")

    with open(f"{fname}-mine.txt", "a") as f:
        f.write(f"{mine}\n")

    with open(f"{fname}-cwnds.txt", "a") as f:
        f.write(f"{cwnds}\n")

    # Kill the sniffer process
    ppid = os.getppid()
    os.kill(ppid, signal.SIGKILL)
    




