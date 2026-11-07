#!/usr/bin/env bash
# Reproduces the Week 9 lab end to end on one Linux host (root needed for the sensor). Output -> week9/evidence/
set -u
cd "$(dirname "$0")/.."; EV=week9/evidence; mkdir -p $EV; : > $EV/runs.jsonl
mark(){ python3 -c "import json,time,sys;print(json.dumps({'run':sys.argv[1],'phase':sys.argv[2],'ts':round(time.time(),6)}))" "$1" "$2" >> $EV/runs.jsonl; }
python3 lab/targets.py > $EV/targets.log 2>&1 & TP=$!
python3 lab/sensor.py $EV/conn.jsonl 2> $EV/sensor.log & SP=$!
sleep 2
mark A_benign start; python3 lab/benign_client.py | tee -a $EV/console.txt; mark A_benign end; sleep 2
mark B_atomic_T1046_1 start; ( time bash lab/atomic_T1046_test1.sh 127.0.0.1 ) 2>&1 | tee $EV/atomic_T1046_1_output.txt | tee -a $EV/console.txt; mark B_atomic_T1046_1 end; sleep 2
mark C_python_fast start; python3 lab/scan_python.py --src 127.0.0.3 --ports 1-1024 --threads 50 | tee -a $EV/console.txt; mark C_python_fast end; sleep 2
mark D_python_slow start; python3 lab/scan_python.py --src 127.0.0.4 --ports 1-40 --threads 1 --delay 3 | tee -a $EV/console.txt; mark D_python_slow end; sleep 2
kill $SP; sleep 1; kill $TP; wait 2>/dev/null; wc -l $EV/conn.jsonl
