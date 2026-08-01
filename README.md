# soc-analyst-agent

A small Claude-powered SOC (Security Operations Center) analyst agent. It has
two capabilities so far, sharing one tool belt and one bounded agent loop:

- **Alert triage & enrichment** — feed it a security alert (JSON with
  indicators like IPs/domains), and it investigates them (WHOIS domain age,
  DNS resolution, reverse DNS, address-space context) and recommends a
  verdict: `escalate`, `monitor`, or `no_action`.
- **Incident / log Q&A copilot** — an interactive chat over a loaded log file.
  Ask it questions ("what happened on finance-ws-07 around 03:14?") and it
  searches/reads the actual log to ground its answers instead of guessing.

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

Both the triage loop and the chat loop are wall-clock- and tool-call-bounded
(`SOCAGENT_MAX_TOOL_CALLS`, `SOCAGENT_TIMEOUT_SECONDS`) so a crafted alert or
log line can't run up cost or hang the CLI.

## Setup

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...   # required for both commands
```

## Usage

Triage a sample alert:

```bash
python -m socagent triage samples/sample_alert.json
```

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
| `SOCAGENT_MAX_TOOL_CALLS` | Tool-call budget per triage/chat turn (default 8). |
| `SOCAGENT_TIMEOUT_SECONDS` | Wall-clock budget per turn (default 30). |
| `SOCAGENT_MAX_LOG_BYTES` / `SOCAGENT_MAX_LOG_LINES` | Cap on how much of a log file is loaded into context (default 2MB / 20,000 lines, most-recent-first). |

## Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

Tests cover the deterministic tools and the verdict-fusion logic only — no
network calls, no LLM calls (WHOIS/DNS are mocked via test seams in
`tools.py`).

## What's next

This is a fresh scaffold, not a finished product — pitch ideas as they come.
Natural next steps: real threat-intel enrichment (VirusTotal/AbuseIPDB, like
MobileGuard's opt-in OSV.dev lookup for `--online-cve`), ingesting alerts
from a real SIEM/EDR export format instead of hand-written JSON, and a
backtest harness against labeled alert data (as done for PhishScope's
investigator agent) before trusting `fuse_recommendation`'s thresholds.
