"""Builds a small synthetic capture (private RFC1918 / documentation IPs) so the analyzer can be demoed offline."""
from scapy.all import *
c, s = "192.168.1.10", "93.184.216.34"
pk = [
 Ether()/ARP(op=1, psrc=c, pdst="192.168.1.1"),
 Ether()/IP(src=c, dst="8.8.8.8")/UDP(sport=51000, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com")),
 Ether()/IP(src=c, dst=s)/TCP(sport=50500, dport=80, flags="S"),
 Ether()/IP(src=s, dst=c)/TCP(sport=80, dport=50500, flags="SA"),
 Ether()/IP(src=c, dst=s)/TCP(sport=50500, dport=80, flags="PA")/Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
 Ether()/IP(src=s, dst=c)/TCP(sport=80, dport=50500, flags="PA")/Raw(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"),
 Ether()/IP(src=c, dst=s)/TCP(sport=50600, dport=443, flags="S"),
 Ether()/IP(src=c, dst="192.168.1.1")/ICMP(),
 Ether()/IP(src="192.168.1.50", dst=c)/TCP(sport=44444, dport=22, flags="S"),
]
for i, p in enumerate(pk): p.time = 1700000000 + i * 0.37
wrpcap("task1_sample.pcap", pk)
print("wrote task1_sample.pcap", len(pk), "packets")
