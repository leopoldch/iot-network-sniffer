import time
from collections import defaultdict
from scapy.all import sniff, ICMP, IP

THRESHOLD = 10  
WINDOW = 1.0    # time window in seconds

history = defaultdict(list)

def handle_icmp(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  
        src = pkt[IP].src
        now = time.time()
        history[src] = [t for t in history[src] if now - t < WINDOW]
        history[src].append(now)
        count = len(history[src])
        if count >= THRESHOLD:
            print(f"[ALERT] {src} -> {count} ICMP requests in the last {WINDOW}s (threshold: {THRESHOLD})")

def main():
    print(f"Listening for ICMP packets (alert threshold: {THRESHOLD} req/{WINDOW}s)...")
    sniff(filter="icmp", prn=handle_icmp, store=False)

if __name__ == "__main__":
    main()
