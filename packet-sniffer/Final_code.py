# packet-sniffer/app.py (Stage C: Filtering + Summary)
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.utils import PcapWriter
from datetime import datetime
from pathlib import Path
import argparse, csv

def proto_of(pkt):
    if TCP in pkt: return "TCP"
    if UDP in pkt: return "UDP"
    if ICMP in pkt: return "ICMP"
    if IP in pkt:  return f"IP proto {pkt[IP].proto}"
    return pkt.name

def main():
    parser = argparse.ArgumentParser(description="Packet sniffer with filters + summary")
    parser.add_argument("-i","--iface", default=None, help="Interface (e.g., eth0/wlan0/ens33)")
    parser.add_argument("-f","--filter", default="ip", help="BPF filter (e.g., 'tcp', 'udp', 'port 53')")
    parser.add_argument("-c","--count", type=int, default=0, help="Packets to capture (0=infinite)")
    args = parser.parse_args()

    # paths
    base_dir = Path(__file__).resolve().parent
    log_dir  = base_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path  = log_dir / f"packets_{stamp}.csv"
    pcap_path = log_dir / f"packets_{stamp}.pcap"

    # writers
    csv_file = open(csv_path, "w", newline="")
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["time","src","dst","proto","length"])

    pcap = PcapWriter(str(pcap_path), append=True, sync=True)

    # counters
    stats = {"TCP":0, "UDP":0, "ICMP":0, "OTHER":0}

    print(f"[+] Writing CSV  -> {csv_path}")
    print(f"[+] Writing PCAP -> {pcap_path}")
    print(f"[+] Sniffing on iface={args.iface or 'DEFAULT'} filter='{args.filter}' count={args.count or '∞'}")
    print("[+] Ctrl+C to stop")

    def handle(pkt):
        pcap.write(pkt)
        ts = datetime.now().strftime("%H:%M:%S")
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            proto = proto_of(pkt)
            length = len(pkt)
            print(f"[{ts}] {src} -> {dst} | {proto} | len={length}")
            csv_writer.writerow([ts, src, dst, proto, length])
            if proto in stats:
                stats[proto] += 1
            else:
                stats["OTHER"] += 1

    try:
        sniff(prn=handle, store=False, iface=args.iface, filter=args.filter, count=args.count)
    except KeyboardInterrupt:
        pass
    finally:
        csv_file.flush(); csv_file.close()
        print("\n[+] Capture finished. Summary:")
        for k,v in stats.items():
            print(f"   {k}: {v} packets")
        print("[+] CSV/PCAP saved.")

if __name__ == "__main__":
    main()
