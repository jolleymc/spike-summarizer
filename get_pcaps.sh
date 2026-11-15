#!/usr/bin/env bash
# Downloads the PCAP + notes zips for the spike scenarios from malware-traffic-analysis.net,
# unzips them into ~/pcaps/<scenario>/ and copies the write-up notes to C:\spike\notes.
# Only the traffic (pcap) and notes zips are downloaded - never the malware-sample zips.
# Usage (Ubuntu):  bash /mnt/c/spike/get_pcaps.sh
set -u
OUT="$HOME/pcaps"; ZIPS="$OUT/zips"; NOTES=/mnt/c/spike/notes
mkdir -p "$ZIPS" "$NOTES"
UA="Mozilla/5.0"
SITE="https://www.malware-traffic-analysis.net"
echo "The zip password is on $SITE/about.html"
read -r -p "Paste the zip password (Enter to try the default patterns): " PW

SCENARIOS="
s01-cncmachinerms-rat 2026/11/12/index.html
s02-screenconnect-backdoor 2026/09/14/index.html
s03-xworm 2026/09/08/index.html
s04-lumma-stealer 2026/08/10/index.html
s05-remcos-rat 2026/08/06/index.html
s06-xloader-formbook 2026/04/13/index.html
s07-guloader-agenttesla 2026/02/03/index.html
s08-kongtuke-mintsloader 2026/02/02/index.html
s09-phantomstealer 2026/01/30/index.html
s10-njrat-masslogger 2026/01/29/index.html
spare-vip-recovery 2026/01/20/index2.html
spare-lumma-followup 2026/01/14/index.html
"

echo "$SCENARIOS" | while read -r name page; do
  [ -z "$name" ] && continue
  dir="${page%/*}"; date=$(echo "$dir" | tr -d '/')
  echo; echo "=== $name  ($SITE/$page)"
  html=$(wget -q -U "$UA" -O - "$SITE/$page") || { echo "  could not load the post page"; continue; }
  echo "$SITE/$page" > "$NOTES/$name.url"
  links=$(echo "$html" | grep -oiE 'href="[^"]+\.zip"' | sed -E 's/^href="//I; s/"$//' \
          | grep -iE 'pcap|traffic|notes|ioc' | grep -viE 'malware|files' | sort -u)
  [ -z "$links" ] && { echo "  no pcap/notes zip links found"; continue; }
  mkdir -p "$OUT/$name" "$ZIPS/$name"
  for l in $links; do
    case "$l" in http*) url="$l";; /*) url="$SITE$l";; *) url="$SITE/$dir/$l";; esac
    f="$ZIPS/$name/$(basename "$l")"
    [ -s "$f" ] || wget -q --show-progress -U "$UA" -O "$f" "$url" || { echo "  download failed: $url"; continue; }
    ok=""
    for p in "$PW" "infected_$date" "infected"; do
      [ -z "$p" ] && continue
      if unzip -o -q -P "$p" "$f" -d "$ZIPS/$name/x" 2>/dev/null; then ok=1; break; fi
    done
    [ -z "$ok" ] && echo "  could not unzip $(basename "$f") - check the password"
  done
  find "$ZIPS/$name/x" -type f \( -iname '*.pcap' -o -iname '*.pcapng' \) -exec mv -f {} "$OUT/$name/" \; 2>/dev/null
  find "$ZIPS/$name/x" -type f -iname '*.txt' -exec sh -c 'cat "$1" >> "$2"; echo >> "$2"' _ {} "$NOTES/$name.txt" \; 2>/dev/null
  rm -rf "$ZIPS/$name/x"
  echo "  pcaps: $(ls "$OUT/$name" 2>/dev/null | wc -l)   notes: $([ -s "$NOTES/$name.txt" ] && echo yes || echo none)"
done
echo; echo "Done. PCAPs are in $OUT, notes in C:\\spike\\notes"
