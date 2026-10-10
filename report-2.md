# Week 5 — Threat Hunting Concept
### Applied to: Port Scanning and Reconnaissance

**Group:** CS-2427
**Date:** 10.10.2026
**Team members:** Tursynbek

---

## 1. Why this week matters for our project

Weeks 1–4 built the *theory and context* for our topic: we defined terms
and classified threat actors (Week 1), collected real reconnaissance
data about a target (Week 2), structured it as IOCs in MISP (Week 3),
and mapped a real breach (Equifax) through the Kill Chain, confirming
that reconnaissance is Stage 1 of almost every intrusion (Week 4).

This week is the first time we actually **hunt** — querying logs
ourselves to look for evidence of the exact activity we have spent four
weeks studying, instead of reading about it or collecting external
indicators.

---

## 2. Two hunting models (from the lecture)

| Model | How it starts | Example |
|---|---|---|
| **Intel-driven hunting** | Starts from external threat intelligence (an IOC, a TTP report, a new CVE) and asks "do we see this in our environment?" | "A new APT report lists IP X as C2 infrastructure — do our logs show any host talking to X?" |
| **Hypothesis-driven hunting** | Starts from a reasoned assumption about attacker behavior, even without a specific external IOC, and searches logs to confirm or reject it | "If someone is scanning us, we should see one source IP touching many destination ports in a short time" |

We chose **hypothesis-driven hunting** for this week, per the syllabus
task, because it directly builds on the Week 1 hypothesis we already
wrote but never tested with real log data:

> *"If our organization is a specific target, we should see repeated,
> low-and-slow scanning from a small set of sources against a narrow set
> of our ports/services — rather than the broad, high-volume,
> single-touch pattern typical of internet-wide scanners."*

---

## 3. Formal hunting hypothesis for this week

**Hypothesis:** *If port-scanning reconnaissance (Kill Chain Stage 1,
ATT&CK T1595 — Active Scanning) is occurring against our monitored host,
our connection/firewall logs will show one or more source IPs
connecting to an unusually high number of distinct destination ports in
a short time window, compared to normal background traffic — which
typically touches only a handful of common ports (22, 80, 443, etc.).*

**What would confirm it:** a source IP with a high count of **distinct
destination ports** hit in a short period, especially on ports outside
the normal handful of services we expect to be contacted.

**What would reject it:** no source IP stands out — all traffic touches
only the small set of expected service ports, consistent with normal
usage rather than scanning.

---

## 4. Data needed and how we obtained it

We do not have access to a real production network's firewall logs for
this coursework, so — following the same "collection must be driven by
a purpose" principle from Week 2 — we generated a **synthetic
connection log** that mimics what a real firewall/NetFlow export looks
like, so we have something concrete to hunt against.

**Script:** [`scripts/generate_portscan_logs.py`](../scripts/generate_portscan_logs.py)

The script creates `week5_threat_hunting/sample_logs/firewall_log.csv`
with three types of traffic, all directed at the same host we have used
throughout the project (`45.33.32.156`, the scanme.nmap.org IP from
Week 2–3, kept for continuity with our MISP event):

| Traffic type | Pattern | Source IP |
|---|---|---|
| Normal background traffic | ~200 connections to common ports only (22, 25, 53, 80, 123, 443), many different source IPs | random `203.0.x.x` addresses |
| Simulated fast/broad port scan | 150 distinct ports hit in under 15 seconds (80ms apart) — classic Nmap-style SYN scan signature | `198.51.100.23` |
| Simulated slow/low port scan | 40 distinct ports spread over 2 hours (3 min apart) — the "low-and-slow", harder-to-notice pattern our Week 1 hypothesis specifically called out | `198.51.100.77` |

Run it:
```bash
python3 scripts/generate_portscan_logs.py
```

This gives us a realistic, labeled dataset where we *know* the ground
truth (which IPs are actually scanning) — useful for coursework, since
it lets us verify our hunt query actually finds the right answer before
trusting it on real data.

---

## 5. Setting up the SIEM

We used the **Elastic Stack (Elasticsearch + Kibana)**, deployed as an Elastic Cloud
deployment (Kibana in the browser, no local install needed).

1. In Kibana opened **Integrations → Upload file** and selected
   `firewall_log.csv` (25.1 KB). Kibana analysed the file and showed a
   preview: columns `timestamp`, `src_ip`, `dst_ip`, `dst_port`,
   `protocol`, `action`.
2. Confirmed field mappings — `src_ip` / `dst_ip` detected as **IP**,
   `dst_port` as a **number**, `timestamp` as a **date** (Kibana also added
   a parsed `@timestamp` field).
3. Created a new index named `firewall-logs` and imported the file.
4. Import finished successfully: index created, all docs searchable, data
   view created. The index contains **390 documents**, which matches the
   number of lines written by the generator script (200 benign + 150 fast
   scan + 40 slow scan).

**Screenshot — file preview and field mappings before import:**

![Kibana file upload preview](screenshots/kibana_data_upload.png)

**Screenshot — import completed (index `firewall-logs`):**

![Kibana upload complete](screenshots/kibana_upload_complete.png)

---

## 6. The hunt query

Testing the hypothesis requires counting **distinct destination ports
per source IP**, then looking for outliers. We ran it in Kibana
**Dev Tools → Console** against the `firewall-logs` index.

```json
GET firewall-logs/_search
{
  "size": 0,
  "aggs": {
    "by_source_ip": {
      "terms": { "field": "src_ip", "size": 500 },
      "aggs": {
        "distinct_ports": { "cardinality": { "field": "dst_port" } },
        "first_seen":     { "min": { "field": "@timestamp" } },
        "last_seen":      { "max": { "field": "@timestamp" } },
        "only_scanners": {
          "bucket_selector": {
            "buckets_path": { "ports": "distinct_ports" },
            "script": "params.ports > 20"
          }
        }
      }
    }
  }
}
```

**What this does, in plain terms:**
- `terms` on `src_ip` — groups all log lines by source IP.
- `cardinality` on `dst_port` — counts how many *different* ports each
  source touched (not just how many connections). This is the key
  scan indicator.
- `min` / `max` of `@timestamp` — first and last connection per source,
  so we can compute the duration and tell the fast scan (seconds) from
  the slow scan (hours).
- `bucket_selector` with `> 20` — our threshold: normal traffic only
  touches a handful of common ports, so any source crossing 20+
  distinct ports is suspicious. Only those sources are returned.
- `"size": 500` — must be larger than the number of distinct source IPs
  (202 in our data); `bucket_selector` runs *after* the top-N buckets are
  chosen, so a small `size` could silently cut off scanners.

**Note on a mistake we fixed:** our first attempt used
`"field": "src_ip.keyword"`. Kibana's upload mapped `src_ip` as an `ip`
type, which has no `.keyword` sub-field, so the query returned
`"buckets": []` even though `hits.total` was 390. Using `src_ip` directly
fixed it.

**Screenshot — query and result in Dev Tools:**

*(screenshot: `screenshots/kibana_search_results.png` — run the query above and paste the screenshot here; the result should show two buckets)*

---

## 7. Results

The query returns exactly two source IPs above the threshold. The values
below are the ground truth of the dataset (computed from the same
`firewall_log.csv` that was uploaded; the uploaded file is identical to
the script output with `random.seed(42)`):

| src_ip | distinct_ports | total_connections | first_seen → last_seen | pattern |
|---|---|---|---|---|
| `198.51.100.23` | 150 | 150 | 11:10:00 → 11:10:11 (≈12 s) | Fast, broad scan |
| `198.51.100.77` | 40 | 40 | 13:00:00 → 14:57:00 (≈2 h) | Slow, low-volume scan |
| *(200 other IPs, `203.0.x.x`)* | 1 | 1 each | — | Normal background traffic |

(All times 2026-10-06, UTC.) The highest value among all benign sources
is 1 distinct port, so the 20-port threshold separates scanners from
normal traffic with a very large margin.

---

## 8. Investigation and decision

**Hypothesis: CONFIRMED** (on the synthetic dataset) — two source IPs
show a clearly abnormal number of distinct destination ports compared
to the rest of the traffic, matching the pattern described in our
Week 1 hypothesis: one fast/broad scanner and one slow/low scanner,
consistent with the idea that background noise and targeted recon can
look different even within the same "port scanning" category.

**Next steps this result would normally trigger** (what a real SOC
analyst would do from here):
1. Check `198.51.100.23` and `198.51.100.77` against external reputation
   sources (VirusTotal, as in Week 2) to see if they are already known
   scanning infrastructure
2. Add both IPs as new attributes to our MISP event (Week 3), tagged
   `recon:port-scan`, with `Correlate` enabled
3. Check whether either IP later appears in logs attempting to connect
   to one of the *specific* open ports we found during our own Week 2
   reconnaissance (22, 80) — which would suggest the scan was followed
   by an actual connection attempt, moving from Kill Chain Stage 1 toward
   Stage 3/4

---

## 9. Mapping back to ATT&CK and the Kill Chain

| What we hunted for | Kill Chain Stage | ATT&CK Technique |
|---|---|---|
| Many distinct ports from one source in a short window (fast scan) | 1 — Reconnaissance | T1595 — Active Scanning (closest sub-technique: T1595.001 Scanning IP Blocks) |
| Many distinct ports from one source over a longer window (slow scan) | 1 — Reconnaissance | T1595 — Active Scanning (same technique, evasive timing) |

*Note:* both scanners hit a single host, so we map them to the parent
technique T1595. T1595.002 (Vulnerability Scanning) would only apply if
we saw evidence of vulnerability-specific probing, which port-level logs
do not show.

This directly continues Week 4's table connecting our own project
activity to the Equifax case: Equifax's own internal scans *failed* to
find their vulnerable Struts instance, while attackers found it. This
week we built and tested the kind of **detection query** that — had
Equifax's defenders been hunting for inbound scanning the same way —
might have surfaced the reconnaissance against ACIS before exploitation
occurred.

---

## 10. Limitations and honesty about the synthetic data

We note clearly: this hunt was run against **data we generated
ourselves**, not real captured traffic. This was a deliberate choice —
we do not have authorized access to a real organization's firewall logs
for this coursework, and generating a labeled synthetic dataset let us
**verify our query logic actually works** (since we know the ground
truth) before it would ever be trusted against real production data. A
real hunt would need to account for messier real-world conditions:
NAT'd source IPs, legitimate multi-port services (e.g., a monitoring
system intentionally checking many ports), and much larger log volumes.

---

## 11. Sources

- Microsoft Threat Hunting Guide (recommended reading for this week)
- Phillip Smith, *Practical Threat Hunting* (recommended reading)
- SANS Threat Hunting Summit presentations
- MITRE ATT&CK — T1595 Active Scanning: https://attack.mitre.org/techniques/T1595/
- Elastic documentation: cardinality aggregation — elastic.co/guide

## AI usage disclosure

Cloud AI (Claude, Anthropic) was used to help write and structure this
report and the synthetic log-generation script, and to debug the
Elasticsearch query (the `.keyword` field issue). The data upload and the
query were executed by the team in our own Elastic Cloud deployment.
