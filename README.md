# Port Scanning and Reconnaissance – Introduction to Threat Hunting (ITH 2026-2027)

Group project, weekly increments for **Week 9 (Atomic Red Team)** and **Week 10 (APT techniques)**, syllabus section 3.3.

| Week | Syllabus task | What we did | Deliverable |
|---|---|---|---|
| 9 | Run atomic tests, analyse results in a SIEM | nmap SYN scans Kali -> Metasploitable 2 (VirtualBox), Wireshark capture, analysis in Splunk; plus automated loopback reproduction of Atomic T1046 #1 | [`week9/REPORT.md`](week9/REPORT.md) ([PDF](week9/REPORT.pdf)) |
| 10 | Analyse APT29/APT41 TTPs, map to ATT&CK | Recon and discovery TTPs of both groups, Navigator layer, hunting hypotheses | [`week10/REPORT.md`](week10/REPORT.md) ([PDF](week10/REPORT.pdf)) |
| Defense | 7–8 min per group | Timed script and Q&A | [`defense/DEFENSE_SCRIPT.md`](defense/DEFENSE_SCRIPT.md) |

```
lab/      targets, sensor, atomic test, scanners, run_lab.sh
detect/   detect_scan.py, make_figures.py, siem/ (Sigma, Splunk, ES|QL)
week9/    REPORT.md + evidence/ (real_lab/ = Splunk query and results; loopback telemetry)
week10/   REPORT.md, ttp_mapping.csv, navigator/ layer
```
Quick start: `sudo ./lab/run_lab.sh && python3 detect/detect_scan.py week9/evidence`

**Ethics:** all scanning is on loopback in an isolated lab. Do not scan systems without written permission.

Team: _<names>_ · Instructor: _<practice teacher>_
