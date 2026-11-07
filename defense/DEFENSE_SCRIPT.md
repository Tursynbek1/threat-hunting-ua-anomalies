# Defense script – 7–8 minutes (weekly increment, weeks 9–10)

| Time | Slide / screen | Say |
|---|---|---|
| 0:00–0:40 | README, topic | Topic: Port Scanning and Reconnaissance. Weeks 9–10 of ITH: Atomic Red Team and APT techniques. We applied both to our topic. |
| 0:40–1:30 | GitHub commits page | Two weekly commits, `week9/` and `week10/`, everything reproducible: scripts, raw telemetry, reports. |
| 1:30–2:30 | `week9/REPORT.md` §2–4 | Syllabus example is T1059/T1003; ours is **T1046 Network Service Discovery**. Lab: Kali 192.168.1.101 scans Metasploitable 2 192.168.1.100; pfSense is the gateway. Atomic T1046 Test #1 (bash loop, 30 open ports) and Test #2 (`nmap -sS /24 -p 80`, 3 hosts up), then two nmap SYN scans captured in Wireshark. |
| 2:30–4:30 | Splunk screenshot `w9_splunk_result.png` | 1 200 events, two scans from one source: 1000 ports in 0.07 s (≈13 700 SYN/s) and 200 ports in 80 s (2.5/s). Grouped by source port. `-T2` still trips a 10-second rule (≈ +7.6 s); only a 3 s delay evades it (loopback reproduction: caught only by the 120 s rule). |
| 4:30–5:15 | Finding + limits | Full-range scan (Test #1) found 30 open ports vs 23 for the default top-1000 scan. |
| 4:30–5:15 | Limits of the lab | pfSense does not see the traffic (same segment), so detection comes from the capture on the attacker, analysed in Splunk from a CSV export. |
| 5:15–6:30 | `week10/REPORT.md` matrix figure | APT29 vs APT41. APT41 does real port scanning (WIDETONE, T1046) and uses Acunetix, JexBoss, fofa.su. APT29: vulnerability scanning, then AD/Azure AD discovery. So APT41 → network rules, APT29 → identity telemetry. |
| 6:30–7:15 | Hypotheses table | Five hunting hypotheses, H1 tested in Week 9. |
| 7:15–8:00 | Limitations + next | Loopback only; Splunk analysis ran on an exported CSV, Sigma/ES|QL rules are written but not executed; next week: run in the university SIEM / tune thresholds. |

## Likely questions
* **Why not T1059/T1003?** They are examples in the syllabus ("e.g."); we chose the techniques of our own topic.
* **Is it a SIEM?** The cloud lab used a Python correlator with the same logic; Splunk/ES|QL/Sigma versions are in `detect/siem/`. State this openly.
* **Why 20 ports / 10 s?** Chosen for a small lab sample; a production value must be tuned on baseline traffic and allow-list scanners.
* **How could the attacker evade PS-2?** Even slower or distributed scanning (many sources) – needs per-destination correlation.
* **T1046 vs T1595.001?** Same behaviour; T1595.001 is outside, pre-compromise (Reconnaissance); T1046 is discovery from inside.
