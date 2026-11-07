# Lab

| File | Role |
|---|---|
| `targets.py` | Imitation services on 127.0.0.1 (ports 22, 80, 443, 3306, 8080, 8443) |
| `sensor.py` | AF_PACKET sniffer on `lo` -> JSON lines (SYN / SYNACK / RSTACK), a stand-in for Zeek / firewall logs |
| `atomic_T1046_test1.sh` | Atomic Red Team T1046 Test #1 "Port Scan" (original command, host = 127.0.0.1) |
| `scan_python.py` | Own TCP connect scanner (fast and slow runs) |
| `benign_client.py` | Normal client for the false-positive check |
| `run_lab.sh` | Runs everything (needs root, Linux, ~4 min) and writes `week9/evidence/` |

Safety: everything uses loopback addresses only. Never point these scripts at systems you do not own or have written permission to test.
