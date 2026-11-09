# CodSoft Cyber Security Internship – Tasks 1, 2 & 3

| Task | Files |
|---|---|
| **1. Network Packet Analyzer** (Python + Scapy) | `task1_packet_analyzer.py`, `task1_make_sample_pcap.py`, `task1_sample.pcap`, `task1_demo_output.txt`, `task1_packet_analyzer_demo.mp4` |
| **2. Phishing Awareness Program** (interactive web module) | `task2_phishing_awareness.html`, `task2_phishing_awareness_demo.mp4` |
| **3. Secure Code Assessment** (Bandit + manual review) | `task3_vulnerable_app.py`, `task3_secure_app.py`, `task3_SECURITY_REPORT.md`, `task3_bandit_before.txt`, `task3_bandit_after.txt`, `task3_secure_code_assessment_demo.mp4` |

## Task 1 – Network Packet Analyzer
Extracts source/destination IP, protocol, ports, TCP flags, DNS queries and a payload preview, with a protocol summary and CSV/JSON export.
```
pip install scapy
python3 task1_make_sample_pcap.py
python3 task1_packet_analyzer.py --pcap task1_sample.pcap
sudo python3 task1_packet_analyzer.py --count 20 --filter "tcp port 80"   # live capture
```
Capture only on networks you own or are authorised to monitor.

## Task 2 – Phishing Awareness Program
Single-file training module: phishing types, spotting suspicious emails and fake sites, social engineering, tips, case studies and a quiz. Download and open `task2_phishing_awareness.html` in a browser (or enable GitHub Pages and rename it to `index.html`).

## Task 3 – Secure Code Assessment
`task3_vulnerable_app.py` is intentionally insecure and must never be deployed. Run `pip install bandit && bandit task3_vulnerable_app.py`. Findings and fixes are in `task3_SECURITY_REPORT.md`; the hardened version is `task3_secure_app.py`.
