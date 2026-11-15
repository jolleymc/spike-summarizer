# Technical Spike - question and pass marks (set BEFORE running)

Michael Jolley, Team 09 (SAL-4). Requirements: FR-05, NFR-02, NFR-03.

**Question:** Can a local open-weight model (Qwen3 8B in Ollama), given a fact template
built from real Suricata alerts, write incident summaries that are accurate, readable
at grade 8 or below, and contain no made-up indicators?

| Measure | Pass mark |
|---|---|
| Summaries that correctly state the attack type, home device and outside address (checked against answer key) | at least 9 of 10 |
| Summaries at Flesch-Kincaid grade 8.0 or below | 10 of 10 |
| Summaries shown to the user with an IP/number not in the source alerts (after indicator check) | 0 of 10 |
| Recorded, no pass mark: raw model outputs with a made-up value; time per summary | - |

## Scoring rules (set before running the model)

- Data: 10 public PCAPs from malware-traffic-analysis.net, run through Suricata 8.0.8 with ET Open rules (53,494 rules).
  Ground truth for each comes from the post's write-up (see `answer_key.csv`).
- A summary is **correct** only if it (1) names the right home device, (2) names the right outside address
  when the write-up's malicious IP appears in the alerts, and (3) describes the attack type at the level the
  alerts support (e.g. "remote-access tool" or "known-bad server"; the exact malware family is required only
  when an alert names it).
- Scenario swap: the CNCmachineRMS RAT capture (2026-11-12) produced only one unrelated alert, so the sensor
  never detected the infection and no summary could be judged. It was replaced by the spare (VIP Recovery,
  2026-01-20). This sensor-coverage gap is recorded as a finding.
