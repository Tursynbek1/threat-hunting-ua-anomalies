#!/usr/bin/env python3
"""Port-scan detection over the sensor's conn.jsonl (SIEM-equivalent correlation, same logic as detect/*.spl and *.yml).

Rule PS-1 (fast scan): one source touches >= FAST_PORTS distinct destination ports within FAST_WINDOW seconds.
Rule PS-2 (slow scan): one source touches >= SLOW_PORTS distinct destination ports within SLOW_WINDOW seconds.
Rule PS-3 (closed-port ratio): >= 80% of a source's SYNs are answered with RST (needs >= 20 SYNs).
Usage: detect_scan.py EVIDENCE_DIR"""
import json, sys, collections, os

FAST_PORTS, FAST_WINDOW = 20, 10
SLOW_PORTS, SLOW_WINDOW = 15, 120
RATIO, MIN_SYN = 0.80, 20

ev = sys.argv[1]
import gzip
rows = [json.loads(l) for l in (gzip.open(os.path.join(ev, "conn.jsonl.gz"), "rt") if os.path.exists(os.path.join(ev, "conn.jsonl.gz")) else open(os.path.join(ev, "conn.jsonl")))]
runs = {}
for l in open(os.path.join(ev, "runs.jsonl")):
    r = json.loads(l); runs.setdefault(r["run"], {})[r["phase"]] = r["ts"]
rows = [r for r in rows if not (r["event"] == "SYN" and r["dst"] != "127.0.0.1")]

syn = collections.defaultdict(list)           # src -> [(ts, dport)]
rst = collections.Counter(); synack = collections.defaultdict(set)
for r in rows:
    if r["event"] == "SYN": syn[r["src"]].append((r["ts"], r["dport"]))
    elif r["event"] == "RSTACK": rst[r["dst"]] += 1                 # reply goes back to the scanner
    elif r["event"] == "SYNACK": synack[r["dst"]].add(r["sport"])

def first_hit(events, nports, window):
    """earliest timestamp at which distinct ports in the trailing window reach nports"""
    from collections import deque
    q, cnt = deque(), collections.Counter()
    for ts, p in events:
        q.append((ts, p)); cnt[p] += 1
        while q and q[0][0] < ts - window:
            _, op = q.popleft(); cnt[op] -= 1
            if not cnt[op]: del cnt[op]
        if len(cnt) >= nports: return ts
    return None

def run_of(ts):
    for n, v in runs.items():
        if v["start"] - 0.5 <= ts <= v["end"] + 2: return n
    return "?"

alerts, summary = [], []
for src, ev_ in sorted(syn.items()):
    ev_.sort(); t0, t1 = ev_[0][0], ev_[-1][0]
    ports = {p for _, p in ev_}
    ratio = rst[src] / len(ev_)
    s = dict(src=src, run=run_of(t0), syn_count=len(ev_), distinct_ports=len(ports), duration_s=round(t1 - t0, 2),
             rate_per_s=round(len(ev_) / max(t1 - t0, 0.001), 1), rst_ratio=round(ratio, 3), open_ports=sorted(synack[src]),
             alerts=[])
    for rid, n, w in (("PS-1 fast port scan", FAST_PORTS, FAST_WINDOW), ("PS-2 slow port scan", SLOW_PORTS, SLOW_WINDOW)):
        h = first_hit(ev_, n, w)
        if h:
            s["alerts"].append(rid); alerts.append(dict(rule=rid, src=src, run=s["run"], first_event=t0, alert_ts=h,
                                                      detection_latency_s=round(h - t0, 2), technique="T1046 / T1595.001"))
    if len(ev_) >= MIN_SYN and ratio >= RATIO:
        s["alerts"].append("PS-3 closed-port ratio"); alerts.append(dict(rule="PS-3 closed-port ratio", src=src, run=s["run"],
            first_event=t0, alert_ts=t1, detection_latency_s=round(t1 - t0, 2), technique="T1046"))
    summary.append(s)

json.dump(dict(summary=summary, alerts=alerts), open(os.path.join(ev, "detection_results.json"), "w"), indent=1)
print(f"{'run':20}{'src':12}{'SYNs':>7}{'ports':>7}{'dur(s)':>8}{'rate/s':>8}{'RST%':>7}  alerts")
for s in summary:
    print(f"{s['run']:20}{s['src']:12}{s['syn_count']:>7}{s['distinct_ports']:>7}{s['duration_s']:>8}{s['rate_per_s']:>8}"
          f"{s['rst_ratio']*100:>6.0f}%  {', '.join(a.split()[0] for a in s['alerts']) or '-'}")
print()
for a in alerts: print(f"ALERT {a['rule']:22} src={a['src']:10} run={a['run']:18} latency={a['detection_latency_s']}s")
