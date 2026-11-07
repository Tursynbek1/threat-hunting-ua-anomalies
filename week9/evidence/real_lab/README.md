# Real lab evidence (VirtualBox: Kali, Metasploitable 2, pfSense)

* `splunk_query.spl` – the search that produced the table in `docs/images/w9_splunk_result.png` (Splunk Enterprise 10.6.1.1, time range *All time*, 1 200 events from `scan.csv`).
* Put your own raw files here before pushing: `scan.csv` (Wireshark export, SYN packets), `scan.pcapng` (if saved), screenshots `w9_01_...png`.

| src_ip | source port | distinct ports | SYN count |
|---|---:|---:|---:|
| 192.168.1.101 | 47454 | 200 | 200 |
| 192.168.1.101 | 48849 | 1000 | 1000 |

## Screenshots in `docs/images/`
`w9_01_lab_addresses`, `w9_02_pfsense_dashboard`, `w9_03_nmap_default_and_victim_tcpdump`, `w9_04_atomic_t1046_test2_nmap`, `w9_05_atomic_t1046_test1_bash`, `w9_06_wireshark_syn_filter_and_T2_scan`, `w9_splunk_result`.
