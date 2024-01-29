import sys
import getopt
from paramiko.client import SSHClient
import subprocess
import time
from pathlib import Path


SSH_ADDR = '74.235.199.17'
SSH_NAME = "azureuser"
NUM_SAMPLES = 35
# CCAS = ["reno", "cubic", "bbr", "bic", "highspeed", "htcp", "illinois", "scalable", "vegas", "veno", "westwood", "yeah"]
CCAS = ["cubic", "reno", "bbr", "bic", "highspeed", "htcp", "illinois", "scalable", "vegas", "veno", "westwood", "yeah", "cdg", "nv", "hybla"]
# CCAS = ["vegas"]
TIMEOUT = 90


def set_cca(cca, ip_str, username):
    client = SSHClient()
    client.load_system_host_keys()
    client.connect(ip_str, username=username)
    client.exec_command(f"sudo sysctl net.ipv4.tcp_congestion_control={cca}")

# Start taking a trace for this run
def start_tcpdump(interface, trace_name):
    p = subprocess.Popen(["tcpdump", "-i", interface, "port", "80", "-w", trace_name])
    return p

# Reset firewall rule and sleep for a few seconds so OS (hopefully) sends RST packet for previous connections
# Assumes no other iptables rules
def try_send_reset(this_ip):
    subprocess.Popen(["iptables", "-D", "OUTPUT", "1"])
    time.sleep(3)

    # iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 10.0.0.193 -j DROP  
    subprocess.Popen(["iptables", "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-s", this_ip, "-j", "DROP"])

def do_tests(interface, this_ip, ip_str, username):
    run_t = int(time.time())
    print("Run ID:", run_t)
    for cca in CCAS:
        set_cca(cca, ip_str, username)
        if cca in {"cubic", "bic"}:
            this_num_samples = 60
        else:
            this_num_samples = NUM_SAMPLES
        for test_num in range (this_num_samples):
            print("Running test:", cca, test_num)
            try_send_reset(this_ip)
            loc = f"traces/run-{run_t}/{cca}/"
            Path(loc).mkdir(parents=True, exist_ok=True)

            tcpdump_proc = start_tcpdump(interface, loc + f"trace-{test_num}.pcap")

            subprocess.run(["timeout", str(TIMEOUT), "python3", "main.py", "-i", interface, "-f", loc + "vectors"])

            tcpdump_proc.kill()

if __name__ == "__main__":

    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:d:n:l:")
    except getopt.GetoptError:
        print("Input Error")
        sys.exit(2)

    for cmd, arg in opts:
        if cmd in ("-i"):
            interface = arg
        elif cmd in ("-l"):
            this_ip = arg

    do_tests(interface, this_ip, SSH_ADDR, SSH_NAME)

   




    

    

    

