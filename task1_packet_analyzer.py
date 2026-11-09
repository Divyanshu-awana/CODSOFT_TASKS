#!/usr/bin/env python3
"""Task 1 - Network Packet Analyzer (CodSoft Cyber Security Internship).

Captures live packets (needs root/admin) or reads a .pcap file, then shows
source/destination IP, protocol, ports, flags and a payload preview in a table.
Use only on networks you own or are authorised to monitor.

Usage:
  sudo python3 packet_analyzer.py --count 20 --iface eth0 --filter "tcp port 80"
  python3 packet_analyzer.py --pcap sample.pcap --csv out.csv --json out.json
"""
import argparse, csv, json, string
from collections import Counter
from datetime import datetime
from scapy.all import sniff, rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw

PROTOS = {1: "ICMP", 6: "TCP", 17: "UDP"}
TCP_FLAGS = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG"}

def preview(raw: bytes, n=40) -> str:
    text = "".join(chr(b) if chr(b) in string.printable[:-5] else "." for b in raw[:n])
    return text

def parse(pkt, idx):
    rec = dict(no=idx, time=datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3],
               src="-", dst="-", proto="OTHER", sport="", dport="", flags="", length=len(pkt), info="", payload="")
    if pkt.haslayer(ARP):
        a = pkt[ARP]
        rec.update(src=a.psrc, dst=a.pdst, proto="ARP", info="who-has" if a.op == 1 else "is-at")
        return rec
    if pkt.haslayer(IP):
        rec.update(src=pkt[IP].src, dst=pkt[IP].dst, proto=PROTOS.get(pkt[IP].proto, str(pkt[IP].proto)))
    elif pkt.haslayer(IPv6):
        rec.update(src=pkt[IPv6].src, dst=pkt[IPv6].dst, proto="IPv6")
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        rec.update(proto="TCP", sport=t.sport, dport=t.dport,
                   flags="|".join(TCP_FLAGS[f] for f in str(t.flags) if f in TCP_FLAGS))
        if 80 in (t.sport, t.dport): rec["info"] = "HTTP"
        if 443 in (t.sport, t.dport): rec["info"] = "HTTPS (encrypted)"
    elif pkt.haslayer(UDP):
        rec.update(proto="UDP", sport=pkt[UDP].sport, dport=pkt[UDP].dport)
    elif pkt.haslayer(ICMP):
        rec.update(proto="ICMP", info=f"type={pkt[ICMP].type}")
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        rec.update(proto="DNS", info="query " + pkt[DNSQR].qname.decode(errors="ignore"))
    if pkt.haslayer(Raw):
        rec["payload"] = preview(bytes(pkt[Raw].load))
    return rec

def show(rows):
    cols = ["no", "time", "src", "dst", "proto", "sport", "dport", "flags", "length", "info"]
    w = {c: max(len(c), *(len(str(r[c])) for r in rows)) for c in cols}
    line = " | ".join(c.upper().ljust(w[c]) for c in cols)
    print(line); print("-" * len(line))
    for r in rows:
        print(" | ".join(str(r[c]).ljust(w[c]) for c in cols))
        if r["payload"]:
            print(f"      payload: {r['payload']!r}")
    print("\nSummary:", dict(Counter(r["proto"] for r in rows)))
    print("Top talkers:", Counter(r["src"] for r in rows).most_common(3))

def main():
    ap = argparse.ArgumentParser(description="Network Packet Analyzer")
    ap.add_argument("--iface"); ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--filter", default="", help="BPF filter, e.g. 'tcp port 80'")
    ap.add_argument("--pcap", help="read from pcap instead of live capture")
    ap.add_argument("--csv"); ap.add_argument("--json")
    a = ap.parse_args()
    pkts = rdpcap(a.pcap) if a.pcap else sniff(iface=a.iface, count=a.count, filter=a.filter or None)
    rows = [parse(p, i + 1) for i, p in enumerate(pkts)]
    show(rows)
    if a.csv:
        with open(a.csv, "w", newline="") as f:
            wr = csv.DictWriter(f, fieldnames=rows[0].keys()); wr.writeheader(); wr.writerows(rows)
    if a.json:
        json.dump(rows, open(a.json, "w"), indent=2)

if __name__ == "__main__":
    main()
