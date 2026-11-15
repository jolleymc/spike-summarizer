"""
Technical Spike v2 (follow-up, revised fact template) - Incident Summarizer (FR-05, NFR-02, NFR-03)
Team 09 (SAL-4) - Michael Jolley

Question: Can a local open-weight model, given a fact template built from real
Suricata alerts, write incident summaries that are accurate, at grade 8 or
below, and contain no made-up indicators?

For each scenario folder in ./alerts/<scenario>/eve.json this script:
  1. builds the fact template from the Suricata alerts (stands in for the correlator),
  2. asks the local model (Ollama) to reword it for a homeowner,
  3. scores readability (Flesch-Kincaid grade, textstat 0.7.4),
  4. runs the indicator check: every IP and every number in the summary must
     appear in the facts; if not, the template draft is used instead,
  5. auto-checks the summary against answer_key.csv (attack type keyword,
     internal IP, external IP),
and writes results.csv, summaries.md and spike_log.txt.

Usage (Windows PowerShell, in C:\\spike):
    python spike.py                 # uses qwen3:8b
    python spike.py --model llama3.1:8b
"""
import argparse, csv, datetime as dt, ipaddress, json, os, platform, re, sys, time
from collections import Counter
from pathlib import Path

import requests
import textstat

HERE = Path(__file__).resolve().parent
OLLAMA = os.environ.get("OLLAMA_URL", "http://localhost:11434")

PASS = {"correct_min": 9, "fk_max": 8.0, "fabricated_final_max": 0}

SYSTEM_PROMPT = (
    "You write short security incident summaries for a homeowner with no security background.\n"
    "Rules:\n"
    "1. Use ONLY the facts provided. Never add an IP address, port, time, date, count or name that is not in the facts.\n"
    "2. Write 3 to 5 short sentences in plain English, at an 8th-grade reading level or easier. Avoid jargon; if you must use a term, explain it in a few words.\n"
    "3. Say what happened, which device on the home network was involved, and what it talked to.\n"
    "4. State the severity exactly as given (Low, Medium or High).\n"
    "5. If an alert name includes a malware or tool name (for example Lumma, Remcos, njRAT, Agent Tesla, ScreenConnect), say that name and explain in a few words what that kind of program does.\n"
    "6. The facts list the most important alert and outside address first. Mention that outside address by number.\n"
    "7. End with one next step a homeowner can actually do, such as disconnecting the device from Wi-Fi, running a malware scan, or changing passwords from a different device. Do not tell them to change router or firewall settings.\n"
    "Output only the summary text."
)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
NUM_RE = re.compile(r"\b\d+(?:[.,:]\d+)*\b")


def log(fh, *parts):
    line = " ".join(str(p) for p in parts)
    print(line)
    fh.write(line + "\n")
    fh.flush()


HOME_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_internal(ip):
    """Home network = the RFC 1918 private ranges (what a home router hands out)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and any(a in n for n in HOME_NETS)


def load_alerts(eve_path):
    alerts = []
    with open(eve_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event_type") == "alert":
                alerts.append(ev)
    return alerts


def fmt_time(ts):
    # Suricata: 2026-01-14T18:22:05.123456+0000
    try:
        t = dt.datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
        return t.strftime("%H:%M UTC on %b %d, %Y").replace(" 0", " ")
    except Exception:
        return ts


PRIORITY = ("ET MALWARE", "ET TROJAN", "ET CNC", "ET EXPLOIT_KIT", "ET REMOTE_ACCESS", "ET DROP",
            "ET HUNTING", "ET MOBILE_MALWARE", "ET PHISHING", "ET ATTACK_RESPONSE")


def rank(sig):
    """0 = names a threat (malware, exploit kit, remote-access tool, blocklist); 1 = informational noise."""
    return 0 if sig.startswith(PRIORITY) else 1


def build_facts(alerts):
    """v2 fact template: threat alerts first, router/DNS server excluded, outside addresses from threat alerts first."""
    sigs = Counter(a["alert"].get("signature", "unknown") for a in alerts)
    sev = min(a["alert"].get("severity", 3) for a in alerts)
    label = {1: "High", 2: "Medium"}.get(sev, "Low")
    times = sorted(a["timestamp"] for a in alerts)
    internal, ext_hi, ext_lo, ports = Counter(), Counter(), Counter(), Counter()
    for a in alerts:
        r = rank(a["alert"].get("signature", ""))
        for ip_key, port_key in (("src_ip", "src_port"), ("dest_ip", "dest_port")):
            ip = a.get(ip_key)
            if not ip:
                continue
            if is_internal(ip):
                if a.get(port_key) == 53:   # the router answering DNS is not the device at risk
                    continue
                internal[ip] += 1
            else:
                (ext_hi if r == 0 else ext_lo)[ip] += 1
                if a.get(port_key):
                    ports[a[port_key]] += 1
    outside = [ip for ip, _ in ext_hi.most_common(4)]
    outside += [ip for ip, _ in ext_lo.most_common(6) if ip not in outside][: max(0, 4 - len(outside))]
    ordered = sorted(sigs.items(), key=lambda kv: (rank(kv[0]), -kv[1]))
    return {
        "alert_count": len(alerts),
        "first_seen": fmt_time(times[0]),
        "last_seen": fmt_time(times[-1]),
        "home_devices": [ip for ip, _ in internal.most_common(2)],
        "outside_addresses": outside,
        "outside_ports": [p for p, _ in ports.most_common(4)],
        "alert_names": [f"{s} ({n}x)" for s, n in ordered[:6]],
        "severity": label,
    }


def facts_text(f):
    return (
        f"Number of alerts: {f['alert_count']}\n"
        f"First alert: {f['first_seen']}\n"
        f"Last alert: {f['last_seen']}\n"
        f"Home network device(s) involved: {', '.join(f['home_devices']) or 'none identified'}\n"
        f"Outside address(es) involved: {', '.join(f['outside_addresses']) or 'none identified'}\n"
        f"Outside port(s): {', '.join(str(p) for p in f['outside_ports']) or 'none'}\n"
        f"Most important alert: {f['alert_names'][0] if f['alert_names'] else 'none'}\n"
        f"All alert names (from Suricata, most important first): {'; '.join(f['alert_names'])}\n"
        f"Severity: {f['severity']}"
    )


def template_draft(f):
    """The fallback the user sees if the model's text fails the indicator check."""
    dev = ", ".join(f["home_devices"]) or "a device on your network"
    out = ", ".join(f["outside_addresses"]) or "an outside address"
    top = f["alert_names"][0].rsplit(" (", 1)[0] if f["alert_names"] else "a security rule"
    return (
        f"Our sensor raised {f['alert_count']} alerts between {f['first_seen']} and {f['last_seen']}. "
        f"The device at {dev} talked to {out}. "
        f"The main alert was: {top}. "
        f"Severity: {f['severity']}. Next step: disconnect the device and scan it for malware."
    )


def indicator_check(summary, ftext):
    """Every IP and every number in the summary must appear in the facts."""
    allowed_ips = set(IP_RE.findall(ftext))
    fact_wo_ips = IP_RE.sub(" ", ftext)
    allowed_nums = set(NUM_RE.findall(fact_wo_ips))
    # also allow plain components of allowed numbers (e.g. '2026' from a date, '18' from '18:22')
    for n in list(allowed_nums):
        allowed_nums.update(re.split(r"[.,:]", n))
    bad = [ip for ip in IP_RE.findall(summary) if ip not in allowed_ips]
    for n in NUM_RE.findall(IP_RE.sub(" ", summary)):
        if n not in allowed_nums and n.replace(",", "") not in allowed_nums:
            bad.append(n)
    return bad


def ask_model(model, ftext):
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "Facts:\n" + ftext + "\n\nWrite the summary."},
        ],
        "stream": False,
        "think": False,
        "options": {"temperature": 0, "seed": 42},
    }
    t0 = time.time()
    r = requests.post(f"{OLLAMA}/api/chat", json=body, timeout=300)
    r.raise_for_status()
    secs = time.time() - t0
    text = r.json()["message"]["content"]
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    return text, secs


def load_key(path):
    key = {}
    if not path.exists():
        return key
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            key[row["scenario"].strip()] = row
    return key


def auto_score(summary, row):
    if not row:
        return "", "", "", ""
    s = summary.lower()
    kws = [k.strip().lower() for k in row.get("type_keywords", "").split(";") if k.strip()]
    type_ok = any(k in s for k in kws) if kws else ""
    in_ip = row.get("internal_ip", "").strip()
    ex_ip = row.get("external_ip", "").strip()
    in_ok = (in_ip in summary) if in_ip else ""
    ex_ok = (ex_ip in summary) if ex_ip else ""
    checks = [c for c in (type_ok, in_ok, ex_ok) if c != ""]
    return type_ok, in_ok, ex_ok, (all(checks) if checks else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen3:8b")
    ap.add_argument("--alerts", default=str(HERE / "alerts"))
    ap.add_argument("--key", default=str(HERE / "answer_key.csv"))
    args = ap.parse_args()

    tag = args.model.replace(":", "-").replace("/", "-") + "-v2"
    out_dir = HERE / "results" / tag
    out_dir.mkdir(parents=True, exist_ok=True)
    logf = open(out_dir / "spike_log.txt", "w", encoding="utf-8")

    log(logf, "=== Technical Spike FOLLOW-UP run (v2 template; official result is v1)", dt.datetime.now().isoformat(timespec="seconds"))
    log(logf, "Machine:", platform.platform(), "| Python", platform.python_version())
    try:
        log(logf, "Ollama version:", requests.get(f"{OLLAMA}/api/version", timeout=10).json().get("version"))
        info = requests.post(f"{OLLAMA}/api/show", json={"model": args.model}, timeout=30).json()
        d = info.get("details", {})
        log(logf, "Model:", args.model, "| params:", d.get("parameter_size"), "| quant:", d.get("quantization_level"))
    except Exception as e:
        log(logf, "Could not reach Ollama at", OLLAMA, "->", e)
        sys.exit(1)
    log(logf, "Pass marks (set before testing):", json.dumps(PASS))

    key = load_key(Path(args.key))
    scen_dirs = sorted(p for p in Path(args.alerts).iterdir() if (p / "eve.json").exists())
    if key:  # only run the scenarios listed in the answer key (spares are skipped)
        scen_dirs = [p for p in scen_dirs if p.name in key]
    if not scen_dirs:
        log(logf, "No alerts/<scenario>/eve.json files found in", args.alerts)
        sys.exit(1)

    rows, md = [], ["# Spike summaries\n"]
    for sd in scen_dirs:
        name = sd.name
        alerts = load_alerts(sd / "eve.json")
        log(logf, f"\n--- {name}: {len(alerts)} alerts")
        if not alerts:
            log(logf, "   no alerts; skipped")
            rows.append({"scenario": name, "alerts": 0, "note": "no Suricata alerts"})
            continue
        facts = build_facts(alerts)
        ftext = facts_text(facts)
        log(logf, "FACTS:\n" + ftext)
        raw, secs = ask_model(args.model, ftext)
        bad = indicator_check(raw, ftext)
        final = raw if not bad else template_draft(facts)
        fk_raw = textstat.flesch_kincaid_grade(raw)
        fk_final = textstat.flesch_kincaid_grade(final)
        bad_final = indicator_check(final, ftext)
        t_ok, i_ok, e_ok, auto_ok = auto_score(final, key.get(name))
        log(logf, f"MODEL OUTPUT ({secs:.1f}s):\n{raw}")
        log(logf, f"Indicator check: {'PASS' if not bad else 'FAIL, not in facts: ' + ', '.join(bad)}")
        log(logf, f"FK grade raw={fk_raw} final={fk_final} | auto-score type={t_ok} internal_ip={i_ok} external_ip={e_ok}")
        rows.append({
            "scenario": name, "alerts": len(alerts), "severity": facts["severity"],
            "latency_s": round(secs, 1),
            "raw_fabricated": len(bad), "raw_fabricated_values": " ".join(bad),
            "used_fallback": bool(bad), "final_fabricated": len(bad_final),
            "fk_raw": fk_raw, "fk_final": fk_final, "fk_pass": fk_final <= PASS["fk_max"],
            "auto_type_ok": t_ok, "auto_internal_ip_ok": i_ok, "auto_external_ip_ok": e_ok,
            "auto_correct": auto_ok,
            "reviewer_correct": "",  # fill in Y/N yourself after reading the summary against the answer key
            "raw_summary": raw, "final_summary": final,
        })
        md += [f"## {name}  ({facts['severity']}, {len(alerts)} alerts, {secs:.1f}s)\n",
               "**Facts given to the model**\n", "```\n" + ftext + "\n```\n",
               "**Model output**\n", raw + "\n",
               f"**Indicator check:** {'pass' if not bad else 'FAIL - ' + ', '.join(bad) + ' (template draft shown instead)'}  ",
               f"**Flesch-Kincaid grade:** {fk_final}\n"]

    fields = ["scenario", "alerts", "severity", "latency_s", "raw_fabricated", "raw_fabricated_values",
              "used_fallback", "final_fabricated", "fk_raw", "fk_final", "fk_pass", "auto_type_ok",
              "auto_internal_ip_ok", "auto_external_ip_ok", "auto_correct", "reviewer_correct",
              "raw_summary", "final_summary", "note"]
    with open(out_dir / "results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    (out_dir / "summaries.md").write_text("\n".join(md), encoding="utf-8")

    done = [r for r in rows if r.get("alerts")]
    n = len(done)
    log(logf, "\n=== TOTALS", f"({n} scenarios with alerts)")
    log(logf, f"Raw outputs with a value not in the facts: {sum(1 for r in done if r['raw_fabricated'])} of {n}")
    log(logf, f"Final summaries with a value not in the facts: {sum(1 for r in done if r['final_fabricated'])} of {n} (pass mark: 0)")
    log(logf, f"Final summaries at FK grade <= 8.0: {sum(1 for r in done if r['fk_pass'])} of {n} (pass mark: all)")
    log(logf, f"Auto-score correct (type + IPs): {sum(1 for r in done if r['auto_correct'] is True)} of {n} (pass mark: >= 9; confirm by hand in reviewer_correct)")
    if n:
        log(logf, f"Mean model time: {sum(r['latency_s'] for r in done)/n:.1f}s, max {max(r['latency_s'] for r in done):.1f}s")
    log(logf, "Wrote", out_dir)
    logf.close()


if __name__ == "__main__":
    main()
