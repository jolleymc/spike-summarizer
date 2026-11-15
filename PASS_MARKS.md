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
