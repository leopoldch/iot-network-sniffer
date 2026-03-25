import argparse
import time
from scapy.all import IP, ICMP, send

def main():
    parser = argparse.ArgumentParser(description="ICMP Spoofing")
    parser.add_argument("target", help="target IP")
    parser.add_argument("-s", "--source", default="10.10.10.10", help="IP source falsified")
    parser.add_argument("-c", "--count", type=int, default=30, help="NUmber of packet")
    parser.add_argument("-d", "--delay", type=float, default=0.02, help="Delay between packets (s)")
    args = parser.parse_args()

    pkt = IP(src=args.source, dst=args.target) / ICMP()

    print(f"Sending {args.count} ICMP: {args.source} -> {args.target} (delay {args.delay}s)")
    for i in range(args.count):
        send(pkt, verbose=False)
        print(f"  Packet {i+1}/{args.count} sent")
        time.sleep(args.delay)
    print("Finished.")

if __name__ == "__main__":
    main()
