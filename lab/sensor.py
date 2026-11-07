#!/usr/bin/env python3
"""Minimal network sensor (Zeek/firewall-log substitute) for the loopback lab.
Captures TCP handshake packets on `lo` via AF_PACKET and writes one JSON line per event:
  SYN     - connection attempt (SYN without ACK)
  SYNACK  - port open   (SYN+ACK reply)
  RSTACK  - port closed (RST+ACK reply)
Needs root. Usage: sensor.py OUTFILE"""
import socket, struct, sys, time, json, signal

out = open(sys.argv[1], "w", buffering=1)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
s.bind(("lo", 0))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 * 1024 * 1024)
stop = False
def _stop(*a):
    global stop; stop = True
signal.signal(signal.SIGTERM, _stop); signal.signal(signal.SIGINT, _stop)
s.settimeout(0.5)
n = 0
while not stop:
    try:
        pkt, addr = s.recvfrom(65535)
    except socket.timeout:
        continue
    if addr[2] != 4:            # lo delivers each packet twice; keep only the outgoing copy
        continue
    ts = time.time()
    ip = pkt[14:]
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
        continue
    ihl = (ip[0] & 15) * 4
    sport, dport, _, _, off, fl = struct.unpack("!HHIIBB", ip[ihl:ihl + 14])
    syn, ack, rst = fl & 2, fl & 16, fl & 4
    if syn and not ack: kind = "SYN"
    elif syn and ack:   kind = "SYNACK"
    elif rst and ack:   kind = "RSTACK"
    else: continue
    out.write(json.dumps({"ts": round(ts, 6), "event": kind, "src": socket.inet_ntoa(ip[12:16]), "sport": sport,
                          "dst": socket.inet_ntoa(ip[16:20]), "dport": dport}) + "\n")
    n += 1
print("sensor stopped, events:", n, file=sys.stderr)
