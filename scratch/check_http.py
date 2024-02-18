import subprocess
import requests
import random

def start_tcpdump(interface, trace_name, host):
    p = subprocess.Popen(["tcpdump", "-i", interface, "port", "80", "or", "port", "443", "and", "host", host, "-w", trace_name])
    return p

def read_csv(fname):
    with open(fname) as f:
        lines = f.readlines()[1:]
        splits = [line.removesuffix('\n').split(',') for line in lines]
    return [split for split in splits if len(split) == 2]

def to_http(url):
    if url.startswith("https://"):
        url = "http://" + url[8:]
    return url

if __name__ == "__main__":
    urls = read_csv("ccanalyzer-websites-urls.csv")
    random.shuffle(urls)
    # to_http(urls)
    
    tcpdump = start_tcpdump("wlo1", "http_check.pcap")
    
    for url in urls[:20]:
        # r = requests.get(url[1])
        r2 = requests.get(to_http(url[1]))
        print(r2.status_code, to_http(url[1]))

        # print(r.status_code, len(r.text), r2.status_code, len(r2.text))
    tcpdump.kill()
    


