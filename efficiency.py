import glob
import subprocess
import json

RUN_ID = "azure-cloudlab-fixed"
CCAS = ["cubic", "reno", "bbr", "bic", "highspeed", "htcp", "illinois", "scalable", "vegas", "veno", "westwood", "yeah", "cdg", "nv", "hybla"]

def get_metrics_cca(run, cca):
    tcpdump_filenames = glob.glob(f"traces/run-{run}/{cca}/*.pcap")
    total_bytes = 0
    total_time = 0
    for tcpdump_filename in tcpdump_filenames:
        try:
            tshark_cmd = (f'tshark -r {tcpdump_filename} ' \
                        '-Y "tcp.srcport==80 or tcp.dstport==80" ' \
                        '-Tfields -e frame.len -e frame.time_relative')
            print(f'Running {tshark_cmd}')
            tshark_results = subprocess.run(tshark_cmd,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')

            tshark_results_list =  list(map(str.split, tshark_results.split('\n')))[:-1]
            bytes_transfer_tcpdump = sum([int(line.split('\t')[0]) for line in tshark_results.split('\n')[:-1]])
            time_seconds_tcpdump = float(tshark_results_list[-1][1]) - float(tshark_results_list[0][1])

            total_bytes += bytes_transfer_tcpdump
            total_time += time_seconds_tcpdump
        except Exception:
            pass
    
    byte_avg = int(total_bytes // len(tcpdump_filenames))
    time_avg = int(total_time // len(tcpdump_filenames))
    return {"bytes_transferred_avg":byte_avg, "time_avg": time_avg}




if __name__ == "__main__":
    res = {}
    
    for cca in CCAS:
        res[cca] = get_metrics_cca(RUN_ID, cca)

    print("cca, bytes_transferred_avg, time_avg")

    for cca in CCAS:
        print(f"{cca}, {res[cca]['bytes_transferred_avg']}, {res[cca]['time_avg']}")
