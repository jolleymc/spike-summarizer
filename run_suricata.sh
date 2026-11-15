#!/usr/bin/env bash
# Runs Suricata offline on every scenario folder (or single PCAP) and writes one eve.json per scenario.
# Usage (Ubuntu):  bash /mnt/c/spike/run_suricata.sh ~/pcaps /mnt/c/spike/alerts
set -u
PCAPS="${1:-$HOME/pcaps}"
OUT="${2:-/mnt/c/spike/alerts}"
mkdir -p "$OUT"
suricata -V | tee "$OUT/suricata_version.txt"
echo "Rules loaded: $(sudo grep -c '^alert' /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo unknown)" | tee -a "$OUT/suricata_version.txt"
: > "$OUT/run_summary.txt"
for p in "$PCAPS"/*; do
  [ -e "$p" ] || continue
  name="$(basename "$p")"; name="${name%.pcap}"; name="${name%.pcapng}"
  [ "$name" = "zips" ] && continue
  if [ -d "$p" ]; then ls "$p"/*.pcap* >/dev/null 2>&1 || continue; fi
  mkdir -p "$OUT/$name"
  rm -f "$OUT/$name/eve.json"
  sudo suricata -r "$p" -l "$OUT/$name" -k none > "$OUT/$name/suricata_run.txt" 2>&1
  sudo chmod a+r "$OUT/$name"/* 2>/dev/null
  n=$(grep -c '"event_type":"alert"' "$OUT/$name/eve.json" 2>/dev/null || echo 0)
  echo "$(date -Is)  $name: $n alerts" | tee -a "$OUT/run_summary.txt"
done
