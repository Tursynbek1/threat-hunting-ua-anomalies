# Week 1 — Cyber Threat Intelligence Fundamentals
### Applied to: Port Scanning and Reconnaissance

**Group:** CS-2427
**Date:** 21.09
**Team members:** Tursynbek

---

## 1. Why this topic matters for CTI

Reconnaissance and port scanning are the **first stage** an attacker (or a
legitimate penetration tester) performs before any exploitation happens.
In the MITRE ATT&CK framework this corresponds to the **Reconnaissance
(TA0043)** tactic, and in the Lockheed Martin Cyber Kill Chain it is
**Stage 1 — Reconnaissance**. Understanding what scanning looks like from
a defender's point of view is the foundation for building detections and
threat hunting hypotheses later in this course.

Threat intelligence about scanning activity helps an organization:
- know which of its own services are exposed to the internet (attack surface)
- distinguish background internet "noise" (mass scanners, researchers,
  botnets) from targeted reconnaissance against the organization specifically
- prioritize which exposed services need patching or firewalling first

---

## 2. Glossary of key CTI / recon terms

| Term | Definition (in our own words) |
|---|---|
| **Reconnaissance** | The information-gathering phase where an attacker learns about a target's systems, network, and people before attacking. |
| **Port scanning** | Systematically probing a range of network ports on a host to discover which ones are open and what services are listening on them. |
| **Active reconnaissance** | Recon that directly interacts with the target (e.g., sending packets via Nmap), which can be logged/detected by the target. |
| **Passive reconnaissance** | Recon that gathers information without touching the target directly (e.g., Shodan, WHOIS, public records, OSINT). |
| **Banner grabbing** | Connecting to an open port and reading the service's response text to identify the software/version running. |
| **Enumeration** | Deeper probing after discovery to extract more detail (usernames, shares, service versions, etc.). |
| **Attack surface** | The total set of points (ports, services, endpoints, accounts) an attacker could potentially use to gain access. |
| **IOC (Indicator of Compromise)** | A forensic artifact (IP, hash, domain) suggesting a system was scanned/compromised. |
| **TTP (Tactics, Techniques, Procedures)** | The behavioral pattern of an attacker — *why*, *how*, and *exact implementation* of an action such as scanning. |
| **CVE** | A publicly catalogued, uniquely identified software vulnerability that a scan may try to detect exposure to. |
| **Scan type — SYN scan ("half-open")** | Sends a SYN packet and reads the reply without completing the TCP handshake; stealthier, less likely to be logged by the application. |
| **Scan type — Connect scan** | Completes the full TCP three-way handshake; more reliable but more visible in logs. |
| **Scan type — UDP scan** | Probes UDP ports; slower and less reliable due to the connectionless nature of UDP. |
| **Threat actor** | Any individual or group performing (or attempting) the scanning/recon activity — ranges from researchers to botnets to APT groups. |
| **OSINT** | Publicly available information used to enrich understanding of a scanning source (WHOIS, ASN ownership, reputation). |

---

## 3. Classifying scanning/reconnaissance threats

### 3.1 By intent / actor type

| Actor type | Typical goal | Example |
|---|---|---|
| **Security researchers / internet-wide scanners** | Academic/commercial mapping of the internet | Shodan, Censys, Rapid7 Sonar crawlers |
| **Penetration testers (authorized)** | Assess an organization's exposure under contract | Internal red team, hired consultancy |
| **Opportunistic/automated botnets** | Find any vulnerable device to add to a botnet | Mirai-style IoT scanners |
| **Targeted threat actors (APT)** | Map a *specific* organization before a deliberate intrusion | Nation-state or criminal group recon prior to an attack |
| **Script kiddies / low-skill attackers** | Broad, noisy scans looking for easy, known vulnerabilities | Mass Nmap/Masscan sweeps of IP ranges |

### 3.2 By technique (mapped to ATT&CK Reconnaissance tactic)

| ATT&CK Technique (example) | Description |
|---|---|
| T1595 – Active Scanning | Attacker directly probes victim infrastructure (IP blocks, vulnerability scans) |
| T1595.001 – Scanning IP Blocks | Sweeping ranges of IPs to find live hosts |
| T1595.002 – Vulnerability Scanning | Probing for known, specific vulnerabilities (e.g., CVEs) |
| T1592 – Gather Victim Host Information | Passive gathering of hardware/software/firmware info |
| T1590 – Gather Victim Network Information | DNS, network topology, IP ranges gathered passively |

### 3.3 By source (per the ENISA Threat Landscape approach)

- **External/internet-facing:** scans that reach our systems from the public internet, often mass/automated.
- **Internal:** reconnaissance performed by an attacker who has already gained an initial foothold and is now mapping the internal network (this is a strong indicator of an active breach, not a bystander scan).

---

## 4. Why this classification matters for the rest of the project

Distinguishing "background internet noise" from "targeted reconnaissance
against us specifically" is the hunting question we will carry forward:

> **Working hypothesis for later weeks:**
> "If our organization is a specific target, we should see repeated,
> low-and-slow scanning from a small set of sources against a narrow set
> of our ports/services — rather than the broad, high-volume,
> single-touch pattern typical of internet-wide scanners."

This hypothesis will be tested with real data collection in Week 2 and
processed/normalized in Week 3.

---

## 5. Sources consulted

- ENISA Threat Landscape Report (recommended reading for this week)
- MITRE ATT&CK — Reconnaissance tactic (TA0043): https://attack.mitre.org/tactics/TA0043/
- Lockheed Martin Cyber Kill Chain whitepaper
- [Add any additional sources your team used]
