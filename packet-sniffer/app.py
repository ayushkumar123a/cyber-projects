
# packet-sniffer/app.py (Stage A: basic print-only sniffer)
from scapy.all import sniff, IP, TCP, UDP, ICMP
import argparse
from datetime import datetime

def proto_of(pkt):
    if TCP in pkt: return "TCP"
    if UDP in pkt: return "UDP"
    if ICMP in pkt: return "ICMP"
    if IP in pkt:  return f"IP proto {pkt[IP].proto}"
    return pkt.name

def show(pkt):
    ts = datetime.now().strftime("%H:%M:%S")
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
        proto = proto_of(pkt)
        print(f"[{ts}] {src} -> {dst} | {proto} | len={len(pkt)}")
    else:
        print(f"[{ts}] {pkt.summary()}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet sniffer (Stage A)")
    parser.add_argument("-i","--iface", default=None, help="Interface (e.g., eth0/wlan0/lo)")
    parser.add_argument("-f","--filter", default="ip", help="BPF filter (e.g., 'tcp', 'udp', 'port 53')")
    parser.add_argument("-c","--count", type=int, default=0, help="Packets to capture (0=infinite)")
    args = parser.parse_args()

    print(f"[+] Sniffing on iface={args.iface or 'DEFAULT'} filter='{args.filter}' count={args.count or '∞'}")
    print("[+] Ctrl+C to stop")
    sniff(prn=show, store=False, iface=args.iface, filter=args.filter, count=args.count)
