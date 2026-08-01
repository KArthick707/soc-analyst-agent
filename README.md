# soc-analyst-agent

A small Claude-powered SOC (Security Operations Center) analyst agent, built
to cover both Tier 1 and Tier 2 work, plus a log Q&A copilot — sharing one
tool belt and one bounded agent loop:

- **Tier 1 triage (`triage`)** — feed it a security alert (JSON with
  indicators like IPs/domains) and it does a fast first pass: gather just
  enough evidence (WHOIS domain age, DNS resolution, reverse DNS,
  address-space context) to decide whether this needs to go further. Output
  is a coarse hand-off decision: `escalate`, `monitor`, or `no_action`. Small
  tool budget, optimized for speed over depth.
- **Tier 2 investigation (`investigate`)** — deep-dives an alert Tier 1
  already escalated (pass `--tier1-report` to hand it that context). Larger
  tool budget, correlates every indicator into one incident narrative instead
  of checking them independently, and outputs a standard P1–P4 priority plus
  concrete recommended actions (e.g. "block this domain," "isolate this
  host") instead of just a hand-off decision.
- **Incident / log Q&A copilot (`chat`)** — an interactive chat over a loaded
  log file. Ask it questions ("what happened on finance-ws-07 around
  03:14?") and it searches/reads the actual log to ground its answers
  instead of guessing.

## Design

Same core principle as this author's [PhishScope](https://github.com/KArthick707/PhishScope)
investigator agent: **the agent recommends, deterministic code decides.**
The LLM only gathers evidence by calling read-only tools; each tool decides
its own `signal` (`malicious` / `suspicious` / `benign` / `neutral`) and a
plain Python function (`fuse_recommendation` in `socagent/agent.py`) maps the
evidence trail to a verdict. The verdict never comes from asking the model
"is this bad?" directly, and triage never auto-clears to "confirmed benign" —
only to "no_action" (nothing escalated). Absence of evidence isn't proof of
safety, and in a SOC context a missed escalation costs a few minutes of
review while a wrongly-cleared alert costs a real incident going unnoticed.

All three loops are wall-clock- and tool-call-bounded so a crafted alert or
log line can't run up cost or hang the CLI. Tier 2 gets a separate, larger
budget (`SOCAGENT_TIER2_MAX_TOOL_CALLS` / `SOCAGENT_TIER2_TIMEOUT_SECONDS`)
than Tier 1/chat (`SOCAGENT_MAX_TOOL_CALLS` / `SOCAGENT_TIMEOUT_SECONDS`),
reflecting that a deep-dive on an already-escalated alert legitimately needs
to check more indicators than a first-pass triage should spend time on.

## Setup

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...   # required for both commands
```

## Usage

Tier 1: triage a sample alert, optionally saving the report:

```bash
python -m socagent triage samples/sample_alert.json --out /tmp/tier1_report.json
```

Tier 2: escalate that same alert for a deeper investigation, handing it the
Tier 1 report as context:

```bash
python -m socagent investigate samples/sample_alert.json --tier1-report /tmp/tier1_report.json
```

(`investigate` also works standalone without `--tier1-report`, e.g. for an
alert that already came in flagged as high-priority.)

Chat over a sample log:

```bash
python -m socagent chat --log samples/sample.log
```

Then ask things like `what process wrote a file to Temp?` or
`is update-cdn-service.info suspicious?`.

## Configuration

All environment variables are optional; see `socagent/config.py` for defaults.

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Required. Claude API key. |
| `SOCAGENT_MODEL` | Model override (default `claude-opus-5`). |
| `SOCAGENT_MAX_TOOL_CALLS` | Tier 1 triage / chat tool-call budget per turn (default 8). |
| `SOCAGENT_TIMEOUT_SECONDS` | Tier 1 triage / chat wall-clock budget per turn (default 30). |
| `SOCAGENT_TIER2_MAX_TOOL_CALLS` | Tier 2 investigate tool-call budget (default 16). |
| `SOCAGENT_TIER2_TIMEOUT_SECONDS` | Tier 2 investigate wall-clock budget (default 60). |
| `SOCAGENT_MAX_LOG_BYTES` / `SOCAGENT_MAX_LOG_LINES` | Cap on how much of a log file is loaded into context (default 2MB / 20,000 lines, most-recent-first). |

## Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

Tests cover the deterministic tools and both fusion functions
(`fuse_recommendation` for Tier 1, `fuse_priority_and_actions` for Tier 2)
only — no network calls, no LLM calls (WHOIS/DNS are mocked via test seams
in `tools.py`).

## What's next

This is a fresh scaffold, not a finished product — pitch ideas as they come.
Natural next steps: real threat-intel enrichment (VirusTotal/AbuseIPDB, like
MobileGuard's opt-in OSV.dev lookup for `--online-cve`), ingesting alerts
from a real SIEM/EDR export format instead of hand-written JSON, an alert
queue so Tier 1 escalations can auto-feed Tier 2 instead of being chained by
hand via `--tier1-report`, and a backtest harness against labeled alert data
(as done for PhishScope's investigator agent) before trusting either fusion
function's thresholds.
