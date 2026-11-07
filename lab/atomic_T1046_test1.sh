#!/usr/bin/env bash
# Atomic Red Team - T1046 Network Service Discovery, Atomic Test #1 "Port Scan" (Linux/macOS)
# Command copied from redcanaryco/atomic-red-team (atomics/T1046/T1046.md), input host = 127.0.0.1 (lab loopback only).
host="${1:-127.0.0.1}"
for port in {1..65535}; do (2>/dev/null echo >/dev/tcp/${host}/$port) && echo port $port is open ; done
