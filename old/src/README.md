# IG

It enables to detect congestion control algorithm

## Building

### Modify path

1. bin/activate

   Modify "VIRTUAL_ENV"

2. main.py

   Modify sys.path.append(...)

   (This is to add path for "sudo python")

### Activate virtual env

`source bin/activate`

## Running

1. drop RST packets

   `sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s {your_ip} -j DROP`

2. usage

   -u url

   -i network interface

3. example

   `sudo python main.py -u www.facebook.com -i enp0s4`

