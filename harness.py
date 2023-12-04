import sys
import getopt
from paramiko.client import SSHClient

SSH_ADDR = '20.106.168.254'
SSH_NAME = "azureuser"

CCAS = ["bbr", "cubic", "reno", "bic", "highspeed", "htcp", "illinois", "scalable", "vegas", "veno", "westwood", "yeah"]

def set_cca(cca, ip_str, username):
    client = SSHClient()
    client.load_system_host_keys()
    client.connect(ip_str, username=username)
    client.exec_command(f"sudo sysctl net.ipv4.tcp_congestion_control={cca}")

# TODO
def start_tcpdump():
    pass

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


    

    

    
