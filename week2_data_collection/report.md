# Week 2 — Data Collection Process
### Applied to: Port Scanning and Reconnaissance

**Group:** CS-2427
**Date:** 22.09
**Team members:** Tursynbek

---

## 1. Hunting question for this week

Following the Week 1 hypothesis, this week's data-collection goal is:

> **What does our own exposed attack surface look like from an outside
> scanner's perspective, and what threat context already exists around
> IPs/services that resemble scanning infrastructure?**

Following the course's collection process:
**Hypothesis → Data needs → Collection → Analysis → Decision**

| Step | Our answer |
|---|---|
| Hypothesis | Our exposed services can be discovered the same way an attacker's recon would discover them; we should know this before they do. |
| Data needs | Open ports/services (passive, via Shodan), reputation of scanning-related IPs (VirusTotal), relationships between infrastructure (Maltego) |
| Collection | See sections 2–4 below |
| Analysis | See section 5 (data source mapping) |
| Decision | Feed into Week 3 processing (MISP) and later hunting hypotheses |

---

## 2. Tool 1 — Shodan ("What is visible from the Internet?")

**Target used:** `scanme.nmap.org` (Nmap's official public scan-test host —
scanning and looking it up is explicitly permitted) and/or our own lab VM.

Example queries used:

```
hostname:scanme.nmap.org
port:22
product:"OpenSSH"
```

**What we recorded:**
- Open ports and the service/product+version banner on each
- Any outdated/vulnerable-looking software versions flagged by Shodan
- Organization/ASN that owns the IP
- Screenshot: ![Shodan lookup — scanme.nmap.org](Снимок экрана — 2026-09-21 в 19.29.52)

**Notes:** Shodan shows what was observed *at scan time* by Shodan's own
crawlers — it does not perform a live scan for us. Exposure can change
between Shodan's last scan and now.

---

## 3. Tool 2 — VirusTotal ("What threat context is already known?")

We looked up:
- The IP address of our lab/test target → reputation, any prior
  detections, passive DNS history
- (If available) an IP address known from public reports to run
  mass-scanning infrastructure (e.g., a documented Mirai/Masscan scanning
  node from a public threat report) → community comments, detection ratios

**What we recorded:**
- Detection ratio (X/90 vendors flagging it) — *interpreted as evidence,
  not a verdict*, per the course's "enrichment, not a verdict" principle
- Any tags such as `scanner`, `masscan`, `shodan-crawler` if present in
  community comments
- Screenshot: `screenshots/virustotal_lookup.png`

---

## 4. Tool 3 — Maltego ("How are these entities connected?")

**Seed entity:** the IP address / domain from section 2 or 3.

Pivoting mindset followed: **Seed → Transform → Inspect → Pivot → Stop**
(we avoided "Run All Transforms" and only pivoted on relevant results).

**Transforms run:**
1. IP → domain(s) resolving to it (reverse DNS / passive DNS)
2. Domain → WHOIS / registrant organization
3. IP → netblock / ASN owner

**What we recorded:**
- Screenshot of the resulting graph: `screenshots/maltego_graph.png`
- Short written interpretation: does this infrastructure look like a
  single organization's legitimate service, a known scanning/research
  provider (e.g., Shodan's own crawler ranges, Censys), or something
  unexplained/suspicious?

---

## 5. Data source mapping

| Source | What it gives us | Best for | Limitation |
|---|---|---|---|
| **Shodan** | Exposed ports/services, banners, certs, org | Understanding our own (or a target's) attack surface | Snapshot in time; not a live scan |
| **VirusTotal** | Reputation, detections, relationships | Checking if an IP/domain is already known-bad | Different engines can disagree; needs corroboration |
| **Maltego** | Visual relationship graph across entities | Finding hidden connections (who owns what) | Only as good as the transforms/data sources connected |
| **Internal logs (future weeks)** | Whether *we* actually saw traffic from these IPs | Confirming real interaction, not just external context | Requires log retention & access |

**External source gives context; internal data (next weeks) tells us
whether our organization was actually touched by this indicator** — per
the "enriching a suspicious domain" principle from the lecture.

---

## 6. Source evaluation applied

For every indicator collected above we asked:
- **Relevance** — does it relate to scanning/recon specifically?
- **Reliability** — is Shodan/VirusTotal's data first-hand or aggregated?
- **Timeliness** — when was this IP/service last observed?
- **Corroboration** — do at least two of our three tools agree?
- **Specificity** — is the indicator precise (a single IP) or too broad (a whole /16 range)?

---

## 7. Ethics & legality note

Only `scanme.nmap.org` and/or our own lab systems were actively probed.
Shodan, VirusTotal, and Maltego were used strictly in their **passive
lookup** capacity against already-public data — no direct scanning of
third-party infrastructure without authorization was performed.

---

## 8. Sources consulted

- Michael Bazzell, *Open Source Intelligence Techniques* (recommended reading)
- OSINT Framework: https://osintframework.com
- Shodan Search Query Fundamentals (official docs)
- VirusTotal official searching guide
