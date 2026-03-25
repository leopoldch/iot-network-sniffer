# Network Security Toolkit

A small collection of Python scripts built with [Scapy](https://scapy.net/) to play around with network traffic.

## What's inside

### `network_sniffer.py`

Listens on a network interface and logs every packet that goes through — TCP, UDP, ICMP, or unknown. You can filter by protocol and pick a specific interface. Hit `Ctrl+C` and it prints a summary of what it caught.

```
sudo python3 network_sniffer.py -i eth0 -f tcp,icmp
```

### `detect_icmp.py`

Watches for ICMP traffic and raises an alert if someone is flooding a host with ping requests (more than 10 requests per second from the same IP by default).

```
sudo python3 detect_icmp.py
```

### `spoof_icmp.py`

Sends ICMP packets with a forged source IP. Useful to test the detection script above — fire this at a target and see if the detector picks it up.

```
sudo python3 spoof_icmp.py 192.168.1.42 -s 10.10.10.10 -c 30
```

## Requirements

- Python 3
- Scapy (`pip install scapy`)
- Root privileges (sniffing and crafting raw packets requires `sudo`)

## Disclaimer

These tools are for **educational purposes only**, built in a controlled lab environment. Don't use them on networks you don't own.
