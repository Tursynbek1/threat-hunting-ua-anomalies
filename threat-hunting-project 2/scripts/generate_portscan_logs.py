"""
generate_portscan_logs.py

Generates a synthetic firewall/connection log (CSV) that mixes:
  - normal background traffic (a handful of common ports, many source IPs)
  - two simulated port-scanning sources (many distinct destination ports,
    low packet count per port, short time window) against our monitored
    host (reusing the scanme.nmap.org IP from Week 2/3 as the "defended"
    host for continuity with our MISP event)

Output: week5_threat_hunting/sample_logs/firewall_log.csv
Columns: timestamp, src_ip, dst_ip, dst_port, protocol, action

This is SYNTHETIC data created for the coursework exercise — it does not
represent real captured network traffic. It is used only so we have a
dataset to ingest into Splunk/ELK and run our hunt query against, since
we do not have a real production network to monitor.
"""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT_DIR = Path("week5_threat_hunting/sample_logs")
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = OUT_DIR / "firewall_log.csv"

DEFENDED_HOST = "45.33.32.156"  # same IP we tracked in Week 2/3 (scanme.nmap.org)
COMMON_PORTS = [22, 25, 53, 80, 123, 443]
ALL_PORTS = list(range(1, 1025))

random.seed(42)  # reproducible output

rows = []
start_time = datetime(2026, 10, 6, 9, 0, 0)

# 1) Normal background traffic: ~200 benign connections to common ports
for i in range(200):
    ts = start_time + timedelta(seconds=random.randint(0, 3600 * 6))
    src_ip = f"203.0.{random.randint(1,254)}.{random.randint(1,254)}"
    rows.append([
        ts.isoformat(), src_ip, DEFENDED_HOST,
        random.choice(COMMON_PORTS), "TCP", "ALLOWED"
    ])

# 2) Simulated port scan #1 — fast, broad scan from a single source
#    (classic Nmap-style SYN scan pattern: many ports, short window)
scanner_1 = "198.51.100.23"
scan_start = start_time + timedelta(hours=2, minutes=10)
scanned_ports_1 = random.sample(ALL_PORTS, 150)
for i, port in enumerate(scanned_ports_1):
    ts = scan_start + timedelta(milliseconds=i * 80)
    rows.append([
        ts.isoformat(), scanner_1, DEFENDED_HOST,
        port, "TCP", "BLOCKED" if port not in COMMON_PORTS else "ALLOWED"
    ])

# 3) Simulated port scan #2 — slower, "low-and-slow" scan (more evasive,
#    spread across a longer window, matching our Week 1 hypothesis about
#    targeted recon looking different from noisy background scans)
scanner_2 = "198.51.100.77"
scan_start_2 = start_time + timedelta(hours=4)
scanned_ports_2 = random.sample(ALL_PORTS, 40)
for i, port in enumerate(scanned_ports_2):
    ts = scan_start_2 + timedelta(minutes=i * 3)
    rows.append([
        ts.isoformat(), scanner_2, DEFENDED_HOST,
        port, "TCP", "BLOCKED" if port not in COMMON_PORTS else "ALLOWED"
    ])

rows.sort(key=lambda r: r[0])

with open(OUT_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "action"])
    writer.writerows(rows)

print(f"Wrote {len(rows)} log lines to {OUT_FILE}")
print(f"Scanner 1 (fast/broad):  {scanner_1} -> {len(scanned_ports_1)} distinct ports")
print(f"Scanner 2 (slow/low):    {scanner_2} -> {len(scanned_ports_2)} distinct ports")
