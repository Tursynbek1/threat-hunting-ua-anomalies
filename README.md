# Introduction to Threat Hunting — Group Project

**Topic:** Port Scanning and Reconnaissance — Detection and Threat Hunting

**Course:** Introduction to Threat Hunting, School of Cybersecurity, Astana IT University
**Academic Year:** 2026–2027

## About this project

This repository documents our group's weekly progress applying the course's
theoretical and practical concepts (CTI, data collection, data processing,
Cyber Kill Chain, ATT&CK, threat hunting) to our chosen topic: **port
scanning and network/host reconnaissance** — the first stage attackers use
to map a target before exploitation.

Our focus is strictly **defensive and analytical**: understanding how
scanning and reconnaissance techniques work so that we can detect,
classify, and hunt for them in our own environment — not performing
unauthorized scans against systems we do not own or have permission to test.

## Repository structure

```
threat-hunting-project/
├── README.md
├── week1_cti_fundamentals/
│   └── report.md          # CTI glossary + threat classification for recon/scanning
├── week2_data_collection/
│   ├── report.md          # OSINT workflow: Shodan, VirusTotal, Maltego
│   └── screenshots/       # evidence screenshots (add your own)
├── week3_data_processing/
│   ├── report.md          # MISP deployment, IOC import, normalization
│   └── screenshots/       # evidence screenshots (add your own)
└── scripts/                # any helper scripts (nmap parsers, log parsers, etc.)
```

## Weekly progress log

| Week | Topic | Status |
|------|-------|--------|
| 1 | CTI Fundamentals | ✅ Draft ready — fill in team specifics |
| 2 | Data Collection Process | ✅ Draft ready — add real screenshots |
| 3 | Data Processing and Exploitation | ✅ Draft ready — add real MISP export |
| 4+ | Cyber Kill Chain, Threat Hunting, ATT&CK... | 🔲 Upcoming |

## Team

Aitzhan Tursynbek

## Ethical note

All scans and lookups referenced in this project are performed either on
**our own lab/test infrastructure** or against **publicly documented
research targets** (e.g., scanme.nmap.org, which explicitly permits
scanning for learning purposes), or use **passive, already-public data**
(Shodan's own index, VirusTotal, public threat reports). No unauthorized
scanning of third-party systems was performed as part of this coursework.

cloud AI was used to write some text