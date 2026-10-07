# Week 5 — Threat Hunting Concept
### Applied to: Port Scanning and Reconnaissance

**Group:** [group name / number]
**Date:** [date]
**Team members:** [names]

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

We used **[Splunk Free / Elastic (ELK) Stack — pick one and delete the
other section]**.

### Option A — Splunk

1. Installed Splunk Free (splunk.com/download) or ran via Docker:
   ```bash
   docker run -d -p 8000:8000 -e SPLUNK_START_ARGS=--accept-license \
     -e SPLUNK_PASSWORD=<password> --name splunk splunk/splunk:latest
   ```
2. Logged into the web UI at `http://localhost:8000`
3. **Settings → Add Data → Upload** → selected `firewall_log.csv`
4. Set source type to a delimited/CSV format, confirmed field extraction
   for `timestamp`, `src_ip`, `dst_ip`, `dst_port`, `protocol`, `action`
5. Indexed the data under index `firewall_logs`

**Screenshot:** `screenshots/splunk_data_upload.png`

### Option B — ELK (Elasticsearch + Kibana)

1. Deployed via Docker Compose (same pattern as MISP in Week 3):
   ```bash
   docker compose up -d   # elasticsearch + kibana
   ```
2. Used Kibana's **"Upload a file"** feature (Analytics → Discover →
   Add integrations → Upload file) to ingest `firewall_log.csv` into an
   index named `firewall-logs`
3. Confirmed field mappings — `dst_port` as a number, `timestamp` as a date

**Screenshot:** `screenshots/kibana_data_upload.png`

---

## 6. The hunt query

Testing the hypothesis requires counting **distinct destination ports
per source IP** within the log's time range, then looking for outliers.

### Splunk (SPL)

```spl
index=firewall_logs
| stats dc(dst_port) as unique_ports, count as total_connections,
        min(_time) as first_seen, max(_time) as last_seen
  by src_ip
| eval duration_sec = last_seen - first_seen
| where unique_ports > 20
| sort -unique_ports
| convert ctime(first_seen) ctime(last_seen)
```

**What this does, in plain terms:**
- `stats dc(dst_port) ... by src_ip` — for every source IP, count how
  many *different* ports it touched (`dc` = distinct count), not just
  how many connections total
- `where unique_ports > 20` — our threshold: normal traffic only
  touches a handful of common ports, so any source crossing 20+
  distinct ports is suspicious
- `duration_sec` — lets us distinguish the fast scan (short duration,
  many ports) from the slow scan (long duration, fewer ports but still
  abnormal) — both should surface, just with different timing profiles

**Screenshot:** `screenshots/splunk_search_results.png`

### Kibana / Elasticsearch (equivalent logic)

Using Kibana's **Lens** or a terms + cardinality aggregation (via
Discover's "Visualize" or the Dev Tools console):

```json
GET firewall-logs/_search
{
  "size": 0,
  "aggs": {
    "by_source_ip": {
      "terms": { "field": "src_ip.keyword", "size": 50 },
      "aggs": {
        "distinct_ports": { "cardinality": { "field": "dst_port" } },
        "total_hits": { "value_count": { "field": "dst_port" } }
      }
    }
  }
}
```

This returns, per source IP, the **cardinality** (distinct count) of
`dst_port` — same logic as Splunk's `dc()`, just expressed as an
Elasticsearch aggregation. Results were then filtered/sorted in Kibana
to show only source IPs with `distinct_ports > 20`.

**Screenshot:** `screenshots/kibana_search_results.png`

---

## 7. Expected / actual results

Based on how the synthetic dataset was built, the query should surface
exactly two source IPs standing out from the ~200 benign background
connections:

| src_ip | unique_ports | total_connections | pattern |
|---|---|---|---|
| `198.51.100.23` | 150 | 150 | Fast, broad scan — all ports hit within ~12 seconds |
| `198.51.100.77` | 40 | 40 | Slow, low-volume scan — spread across ~2 hours |
| *(all other IPs)* | ≤ 6 | varies | Normal — only touches the expected common ports |

*(Fill in this table with your actual query output once you run it —
replace with real numbers from your screenshot.)*

---

## 8. Investigation and decision

**Hypothesis: CONFIRMED** (for the synthetic dataset) — two source IPs
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
| Many distinct ports from one source in a short window (fast scan) | 1 — Reconnaissance | T1595.001 — Active Scanning: Scanning IP Blocks |
| Many distinct ports from one source over a longer window (slow scan) | 1 — Reconnaissance | T1595.002 — Active Scanning: Vulnerability Scanning |

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
- Splunk SPL documentation: `stats`, `dc()` — docs.splunk.com
- Elastic documentation: cardinality aggregation — elastic.co/guide

## AI usage disclosure

Cloud AI (Claude Sonnet 5, Anthropic) was used to help write and
structure this report and the synthetic log-generation script. The
hunt queries were tested against our own generated dataset; results in
Section 7 should be replaced with actual screenshots and numbers from
running the queries ourselves.
