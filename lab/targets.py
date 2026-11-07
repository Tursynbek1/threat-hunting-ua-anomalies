#!/usr/bin/env python3
"""Lab target: opens a few TCP listeners that imitate common services on 127.0.0.1.
Only used inside the isolated lab (loopback). Stops on SIGINT/SIGTERM."""
import socket, threading, signal, sys

SERVICES = {22: b"SSH-2.0-OpenSSH_9.6 lab-target\r\n", 80: b"HTTP/1.1 200 OK\r\nServer: lab-httpd\r\n\r\n",
            443: b"", 3306: b"\x0a8.0.lab-mysql\x00", 8080: b"HTTP/1.1 200 OK\r\nServer: lab-proxy\r\n\r\n",
            8443: b""}

def serve(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(128)
    while True:
        c, _ = s.accept()
        try:
            if SERVICES[port]: c.sendall(SERVICES[port])
        except OSError: pass
        c.close()

if __name__ == "__main__":
    for p in SERVICES: threading.Thread(target=serve, args=(p,), daemon=True).start()
    print("targets listening:", sorted(SERVICES), flush=True)
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    signal.pause()
