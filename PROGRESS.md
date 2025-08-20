
# 📅 Progress Log

## Day 1
- Setup environment (Python venv, installed dependencies).
- Created project folders.
- Started Flask app.

## Day 2
- Manual SQL Injection/XSS test on test site.
- Implemented basic crawler to extract forms & links.
- Saved screenshot in `web-scanner/screenshots/day2_manual_xss.png`.

## Day 3
- Fixed SSH authentication for GitHub (set up SSH key).
- Successfully pushed repo with SSH.
- Cleaned repo structure (removed duplicate files).
- Prepared progress log format for daily updates.

## Day 4
- Started Packet Sniffer project.
- Implemented basic capture using Scapy (source/destination/protocol).
- Added CSV and PCAP logging.
- Saved screenshot in `packet-sniffer/screenshots/day4_sniffer.png`.

## Day 5
- Extended sniffer to support CSV and PCAP logging.
- Evidence: `packet-sniffer/screenshots/day5_stageB.png`


 
 ## Day 6 Progress
- Replaced sniffer with **Stage B code** (CSV + PCAP logging).
- Now captures packets with timestamp, source, destination, protocol, and length.
- Logs saved into `logs/packets_<timestamp>.csv` and `logs/packets_<timestamp>.pcap`.
- Verified by running on `lo` interface with 15 packets.
- Successfully opened `.pcap` in Wireshark for analysis.



---

