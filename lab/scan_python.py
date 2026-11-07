#!/usr/bin/env python3
"""Own re-implementation of a TCP connect scanner (equivalent in spirit to Atomic Test #4 'Port Scan using python').
Used for run B (fast, threaded) and run C (slow / low-and-slow evasion variant). Lab loopback only.
Usage: scan_python.py --src 127.0.0.3 --ports 1-1024 [--threads 50] [--delay 0]"""
import argparse, socket, time
from concurrent.futures import ThreadPoolExecutor

ap = argparse.ArgumentParser()
ap.add_argument("--target", default="127.0.0.1"); ap.add_argument("--src", default="127.0.0.3")
ap.add_argument("--ports", default="1-1024"); ap.add_argument("--threads", type=int, default=50)
ap.add_argument("--delay", type=float, default=0.0, help="seconds between probes (per thread)")
a = ap.parse_args()
lo, hi = map(int, a.ports.split("-"))

def probe(p):
    if a.delay: time.sleep(a.delay)
    s = socket.socket(); s.settimeout(1); s.bind((a.src, 0))
    try:
        s.connect((a.target, p)); return p
    except OSError: return None
    finally: s.close()

t0 = time.time()
with ThreadPoolExecutor(a.threads) as ex:
    openp = sorted(p for p in ex.map(probe, range(lo, hi + 1)) if p)
print(f"scanned {hi-lo+1} ports from {a.src} in {time.time()-t0:.1f}s; open: {openp}")
