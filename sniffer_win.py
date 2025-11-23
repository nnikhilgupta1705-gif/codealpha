#!/usr/bin/env python3
# sniffer_win.py - simpler network sniffer for Windows + Npcap
# Usage: python sniffer_win.py --iface "Wi-Fi" --count 0

import argparse
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP

def human_summary(pkt):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(pkt.time))
    proto = "OTHER"
    src = dst = "-"
    sport = dport = "-"

    ip = pkt.getlayer(IP)
    if ip:
        src = ip.src
        dst = ip.dst
        if pkt.haslayer(TCP):
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
        else:
            proto = "IP"

    length = len(pkt)
    # payload preview (first 40 bytes in hex, ignoring errors)
    try:
        payload = bytes(pkt.payload)[:40]
        payload_preview = payload.hex()
    except Exception:
        payload_preview = ""

    return f"{ts} | {proto} | {src}:{sport} -> {dst}:{dport} | len={length} | {payload_preview}"

def main():
    parser = argparse.ArgumentParser(description="Basic network sniffer (Windows-friendly)")
    parser.add_argument("--iface", "-i", help="Interface name (e.g. \"Wi-Fi\")", default=None)
    parser.add_argument("--count", "-c", type=int, help="Number of packets (0=infinite)", default=0)
    parser.add_argument("--filter", "-f", help="BPF filter, e.g. \"ip\"", default="ip")
    args = parser.parse_args()

    def pkt_cb(pkt):
        print(human_summary(pkt))

    print("Starting sniffing... (Ctrl-C to stop)")
    try:
        sniff(
            iface=args.iface,
            prn=pkt_cb,
            filter=args.filter,  # only IP packets → more stable on Windows
            store=False,         # don't store packets in memory
            count=args.count if args.count > 0 else 0
        )
    except PermissionError:
        print("Permission denied: run this as Administrator.")
    except KeyboardInterrupt:
        print("\nStopped by user.")

if __name__ == "__main__":
    main()
