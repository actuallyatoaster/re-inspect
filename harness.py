import sys
import getopt
from paramiko.client import SSHClient
import subprocess
import time

SSH_ADDR = '20.106.168.254'
SSH_NAME = "azureuser"
NUM_SAMPLES = 10
CCAS = ["cubic", "reno", "bbr", "bic", "highspeed", "htcp", "illinois", "scalable", "vegas", "veno", "westwood", "yeah"]

def set_cca(cca, ip_str, username):
    client = SSHClient()
    client.load_system_host_keys()
    client.connect(ip_str, username=username)
    client.exec_command(f"sudo sysctl net.ipv4.tcp_congestion_control={cca}")

# TODO
def start_tcpdump(interface, trace_name):
    p = subprocess.Popen(["tcpdump", "-i", interface, "port", "80", "-w", trace_name])
    return p

def do_tests(interface, ip_str, username):
    run_t = time.time()
    print("Run ID:", run_t)
    for cca in CCAS:
        set_cca(cca, ip_str, username)
        for test_num in range (NUM_SAMPLES):
            print("Running test:", cca, test_num)
            loc = f"traces/run-{run_t}/{cca}/"
            tcpdump_proc = start_tcpdump(interface, loc + f"trace-{test_num}.pcap")

            subprocess.run(["python3", "main.py", "-i", interface, "-f", loc + "vectors"])

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
        elif cmd in ("-d"):
            res_dir = arg
        elif cmd in ("-n"):
            num = arg
        elif cmd in ("-l"):
            logfile = arg

   




    

    

    

