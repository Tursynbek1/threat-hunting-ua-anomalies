#!/usr/bin/env python3
"""Benign baseline: a normal client from 127.0.0.2 that talks to 3 services a few times (false-positive check)."""
import socket, time
for _ in range(4):
    for p in (80, 443, 8080):
        s = socket.socket(); s.bind(("127.0.0.2", 0)); s.connect(("127.0.0.1", p)); s.close(); time.sleep(0.4)
print("benign client done")
