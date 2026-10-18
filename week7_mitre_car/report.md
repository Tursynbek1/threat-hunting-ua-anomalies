# Week 7 — Using MITRE CAR (Cyber Analytics Repository)
### Applied to: Port Scanning and Reconnaissance

**Group:** CS-2472
**Date:** 18.10
**Team members:** Tursynbek

---

## 1. Why this week matters for our project

Week 5 taught us **hypothesis-driven hunting**: we wrote our own ad-hoc
Elasticsearch aggregation query from scratch to test a hypothesis we
came up with ourselves. This week asks something different: instead of
inventing our own detection logic, we take a **pre-built, published,
community-vetted analytic** from MITRE's **Cyber Analytics Repository
(CAR)** and implement *that* in our SIEM.

**The key conceptual difference this week teaches (CAR's own framing):**

| | Analytic | Detection |
|---|---|---|
| Definition | The abstract logic — *what pattern indicates this technique?* | The concrete, tuned implementation of that logic in a specific product with a specific threshold |
| Example | "Count distinct destination ports per source IP" | "In *our* Splunk/Kibana, alert when that count exceeds 5" |

A CAR analytic is meant to be **adapted**, not copy-pasted — the
published threshold and field names are a starting point, and a real
SOC tunes them to their own environment's normal traffic.

---

## 2. Selecting the analytic — CAR-2021-01-001

We searched the CAR repository (car.mitre.org) for an analytic matching
our project topic and found an exact fit:

| Field | Value |
|---|---|
| CAR ID | **CAR-2021-01-001** |
| Title | Identifying Port Scanning Activity |
| Maps to ATT&CK | **T1046 — Network Service Discovery** |
| Data model | `flow` object, `start` action, `dest_ip` field |
| Source | https://car.mitre.org/analytics/CAR-2021-01-001/ |

**CAR's detection logic (as published):**
1. Select network connections where the destination IP is in the internal subnet
2. For each source IP, count the distinct destination ports it contacted
3. Flag any source IP with **more than 5** distinct destination ports

**CAR's reference Splunk query (as published on the site):**
```spl
sourcetype='firewall_logs' dest_ip = 'internal_subnet'
| stats dc(dest_port) as pcount by src_ip
| where pcount > 5
```

**Why this analytic is a near-perfect continuation of our project:**
this is almost exactly the query logic we already wrote ourselves in
Week 5, independently, before ever looking at CAR — which is a useful
sanity check that our own hypothesis-driven reasoning in Week 5 landed
on the same core idea that MITRE's own published analytic uses.

---

## 3. Honest note on adapting the analytic to our environment

CAR's analytic is written for **internal** network monitoring (an
already-compromised host scanning *other internal* hosts — i.e.
detecting **T1046**, matching our Week 6 simulation). Our existing
`firewall-logs` index in Kibana (built in Week 5) instead represents
**external** traffic arriving at **one** monitored host (matching
**T1595**, external reconnaissance).

We did not pretend these are identical. The **counting logic is
identical and directly reusable** (distinct destination ports per
source IP, thresholded) — only the *direction* and *real-world
technique label* differ:

| | CAR's original intent | Our implementation this week |
|---|---|---|
| Traffic direction | Internal host → other internal hosts | External host → our one monitored host |
| ATT&CK technique detected | T1046 (Discovery) | T1595 (Reconnaissance) |
| Underlying detection math | Same: `count(distinct dst_port) by src_ip`, threshold | Same |

This is a deliberate, documented adaptation — exactly the kind of
tuning CAR expects a real analyst to do, not a mistake.

---

## 4. Implementing the analytic in Kibana

We reused the **same `firewall-logs` index** from Week 5 (390 documents:
200 background connections + two simulated scanners at 150 and 40
distinct ports each) — no new data collection needed, since the
underlying detection logic is identical to what we'd already built.

### Difference from our Week 5 query

Our Week 5 query was an **open-ended aggregation** (show me the port
count for every source IP, we'll eyeball the outliers). CAR's analytic
is a **real detection rule** — it applies the `> 5` threshold
**server-side**, using Elasticsearch's `bucket_selector` pipeline
aggregation, so the query itself returns *only* the flagged IPs, the
way a production detection would.

### The query (Kibana Dev Tools)

```json
GET firewall-logs/_search
{
  "size": 0,
  "aggs": {
    "by_source_ip": {
      "terms": { "field": "src_ip", "size": 200 },
      "aggs": {
        "distinct_ports": { "cardinality": { "field": "dst_port" } },
        "port_scan_filter": {
          "bucket_selector": {
            "buckets_path": { "pcount": "distinct_ports" },
            "script": "params.pcount > 5"
          }
        }
      }
    }
  }
}
```

**What `bucket_selector` does, in plain terms:** it is Elasticsearch's
equivalent of CAR's SPL `| where pcount > 5` line — it runs *after* the
aggregation and **removes** any bucket (any source IP) that doesn't
satisfy the condition, so the only rows left in the response are the
ones CAR's analytic would flag as a probable port scan.

**Screenshot:** `screenshots/car_query_dev_tools.png`

### Expected result

Using CAR's own threshold (`> 5` distinct ports — much lower than the
informal cutoff we eyeballed in Week 5), the response should return
**both** of our simulated scanners, since 150 and 40 both comfortably
exceed 5:

| src_ip | distinct_ports | CAR verdict |
|---|---|---|
| `198.51.100.23` | 150 | 🚩 Flagged (fast scan) |
| `198.51.100.77` | 40 | 🚩 Flagged (slow scan) |
| *(all 152 other IPs)* | 1 | Not flagged — below threshold |

*(Replace with your actual screenshot output once you run it — numbers
should match Week 5's results exactly, since it's the same dataset.)*

---

## 5. Operationalizing it as a real alert (optional, stretch goal)

A Dev Tools query only runs when someone manually clicks "run". A real
SIEM deployment of this analytic would turn it into a **standing alert
rule** that runs automatically:

1. In Kibana: **Stack Management → Rules → Create rule**
2. Rule type: **Elasticsearch query**
3. Index: `firewall-logs`
4. Paste the same query (minus `"size": 0` formatting concerns) as the
   rule's custom query
5. Set the rule to run periodically (e.g., every 5 minutes) and notify
   (email/Slack/webhook action) whenever the query returns 1+ flagged
   buckets

**Screenshot (if completed):** `screenshots/kibana_alert_rule.png`

---

## 6. Mapping back to ATT&CK

| What we implemented | CAR ID | ATT&CK Technique | Tactic |
|---|---|---|---|
| Port-count-per-source-IP detection, threshold-based | CAR-2021-01-001 | **T1046** (as published) / **T1595** (as we adapted it) | Discovery / Reconnaissance |

---

## 7. Conclusion — what this week taught us about detection engineering

1. **Published analytics are starting points, not finished products** —
   CAR gave us the right *shape* of detection logic, but we had to
   consciously decide how it applied to our own data (internal vs.
   external direction) and be honest about that adaptation.
2. **Our own Week 5 hypothesis-driven query independently converged on
   the same logic** that a MITRE-published, peer-reviewed analytic
   uses — a good sign that the reasoning process taught in Week 5
   (hypothesis → data needed → query) produces sound detections even
   without reading the "official" answer first.
3. **`bucket_selector` is the production-grade way to apply a
   threshold**, compared to Week 5's manual eyeballing of results —
   this is the difference between "doing analysis" and "building a
   detection rule."

---

## 8. Sources

- MITRE CAR, CAR-2021-01-001 — Identifying Port Scanning Activity: https://car.mitre.org/analytics/CAR-2021-01-001/
- MITRE CAR Documentation: https://car.mitre.org/
- MITRE ATT&CK, T1046 — Network Service Discovery: https://attack.mitre.org/techniques/T1046/
- Elastic documentation — bucket_selector aggregation: elastic.co/guide

## AI usage disclosure

Cloud AI (Claude Sonnet 5, Anthropic) was used to help research the
CAR analytic, write and structure this report, and draft the
Elasticsearch `bucket_selector` query. The query was adapted from
CAR-2021-01-001's published Splunk SPL and should be run and verified
against our team's real `firewall-logs` index before submission.
