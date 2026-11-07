# SIEM queries equivalent to detect/detect_scan.py

> Status: written for the university SIEM (Splunk / ELK). They were **not** executed in the cloud lab, where the
> same logic was validated with `detect/detect_scan.py`. Adjust index / field names to your data model.

## Splunk SPL
```spl
# PS-1 fast scan: >=20 distinct destination ports from one source in a 10 s bucket
index=network sourcetype=firewall
| bin _time span=10s
| stats dc(dest_port) AS ports, count AS attempts BY _time, src_ip
| where ports >= 20

# PS-2 slow scan: >=15 distinct ports in 120 s (sliding window)
index=network sourcetype=firewall
| streamstats time_window=120s dc(dest_port) AS ports BY src_ip
| where ports >= 15
| stats earliest(_time) AS first_seen, max(ports) AS max_ports BY src_ip

# PS-3 closed-port ratio (TCP reset replies)
index=network sourcetype=firewall
| stats count(eval(tcp_flags="RST")) AS resets, count AS total BY src_ip
| eval ratio=resets/total | where total>=20 AND ratio>=0.8
```

## Elastic ES|QL
```esql
FROM logs-network*
| WHERE network.transport == "tcp"
| STATS ports = COUNT_DISTINCT(destination.port), attempts = COUNT(*) BY src = source.ip, bucket = BUCKET(@timestamp, 10 seconds)
| WHERE ports >= 20
```

## Host-side telemetry for Atomic Test #1 (bash /dev/tcp)
The test opens no external binary, so process-creation logs show only `bash`. Hunt for a **single bash process that
forks thousands of subshells** or for the command line containing `/dev/tcp/` (auditd `execve` / Sysmon for Linux EID 1).
```spl
index=linux sourcetype=auditd type=EXECVE a0="bash" | search "/dev/tcp/"
```
