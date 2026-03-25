import sys
import signal
import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP

counters = {"TCP": 0, "UDP": 0, "ICMP": 0, "Autre": 0}

def print_stats(sig=None, frame=None):
    print("\n\nStats")
    for proto, count in counters.items():
        print(f"  {proto}: {count} packets")
    print(f"  Total: {sum(counters.values())} packets")
    sys.exit(0)

signal.signal(signal.SIGINT, print_stats)

def compute_packet(packet):
    if not packet.haslayer(IP):
        return

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst

    if packet.haslayer(TCP):
        counters["TCP"] += 1
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        print(f"[TCP]  {ip_src}:{sport} -> {ip_dst}:{dport}")

    elif packet.haslayer(UDP):
        counters["UDP"] += 1
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        print(f"[UDP]  {ip_src}:{sport} -> {ip_dst}:{dport}")

    elif packet.haslayer(ICMP):
        counters["ICMP"] += 1
        icmp_type = packet[ICMP].type
        print(f"[ICMP] {ip_src} -> {ip_dst}  (type={icmp_type})")

    else:
        counters["Autre"] += 1
        print(f"[???]  {ip_src} -> {ip_dst}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network sniffer")
    parser.add_argument("-i", "--interface", type=str, default=None,
                        help="Network interface to sniff on (e.g. eth0, wlan0)")
    parser.add_argument("-f", "--filter", type=str, default=None,
                        help="Protocols to capture: tcp,udp,icmp (comma-separated)")
    args = parser.parse_args()

    bpf_filter = None
    if args.filter:
        protos = [p.strip().lower() for p in args.filter.split(",")]
        valid = {"tcp", "udp", "icmp"}
        for p in protos:
            if p not in valid:
                print(f"Unknown protocol: {p} (use tcp, udp, icmp)")
                sys.exit(1)
        bpf_filter = " or ".join(protos)

    print("Capture in progress... (Ctrl+C to stop)")
    if args.interface:
        print(f"Interface: {args.interface}")
    if bpf_filter:
        print(f"Filter: {bpf_filter}")

    sniff(iface=args.interface, filter=bpf_filter, prn=compute_packet, store=False)
