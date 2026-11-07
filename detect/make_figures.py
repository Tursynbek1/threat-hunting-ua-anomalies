#!/usr/bin/env python3
"""Figures for the Week 9 report from week9/evidence/conn.jsonl."""
import json, collections, sys, gzip
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
ev = sys.argv[1]; out = sys.argv[2]
rows = [json.loads(l) for l in gzip.open(f"{ev}/conn.jsonl.gz", "rt")]
syn = collections.defaultdict(list)
for r in rows:
    if r["event"] == "SYN": syn[r["src"]].append((r["ts"], r["dport"]))
names = {"127.0.0.1": "B  Atomic T1046 #1 (bash /dev/tcp)", "127.0.0.2": "A  benign client",
         "127.0.0.3": "C  python scan, fast", "127.0.0.4": "D  python scan, slow (3 s/probe)"}
col = {"127.0.0.1": "#c0392b", "127.0.0.2": "#2e7d32", "127.0.0.3": "#1f6fb2", "127.0.0.4": "#b9770e"}
res = json.load(open(f"{ev}/detection_results.json"))
fig, ax = plt.subplots(1, 2, figsize=(13, 4.8))
for src, e in sorted(syn.items()):
    e.sort(); t0 = e[0][0]; seen = set(); xs, ys = [], []
    for ts, p in e: seen.add(p); xs.append(ts - t0); ys.append(len(seen))
    ax[0].plot(xs, ys, color=col[src], lw=2, label=names[src])
ax[0].set_yscale("log"); ax[0].set_xscale("symlog", linthresh=0.1); ax[0].set_xlim(left=0)
ax[0].axhline(20, color="grey", ls="--", lw=1); ax[0].text(0.12, 22, "PS-1 threshold: 20 ports", fontsize=8, color="grey")
ax[0].set_xlabel("seconds since first SYN (symlog)"); ax[0].set_ylabel("distinct destination ports (log)")
ax[0].set_title("Distinct ports touched per source"); ax[0].legend(fontsize=8, loc="upper left"); ax[0].grid(alpha=.25)
al = collections.defaultdict(dict)
for a in res["alerts"]: al[a["src"]][a["rule"].split()[0]] = a["detection_latency_s"]
srcs = sorted(syn); w = .25
for i, rule in enumerate(["PS-1", "PS-2", "PS-3"]):
    ys = [al[s].get(rule, 0) for s in srcs]
    ax[1].bar([k + (i - 1) * w for k in range(len(srcs))], [max(y, .01) if s in al and rule in al[s] else 0 for y, s in zip(ys, srcs)], w, label=rule)
    for k, (y, s) in enumerate(zip(ys, srcs)):
        if rule in al[s] and y < .01: ax[1].text(k + (i - 1) * w, .013, "<0.01", ha="center", fontsize=7)
    for k, s in enumerate(srcs):
        if rule not in al[s]: ax[1].text(k + (i - 1) * w, .012, "—", ha="center", fontsize=9)
ax[1].set_yscale("log"); ax[1].set_xticks(range(len(srcs))); ax[1].set_xticklabels([names[s].split("  ")[0] for s in srcs])
ax[1].set_ylabel("time from first SYN to alert (s, log)"); ax[1].set_title("Detection latency per rule (— = no alert)")
ax[1].legend(); ax[1].grid(alpha=.25, axis="y")
plt.tight_layout(); plt.savefig(f"{out}/w9_scan_detection.png", dpi=150)
