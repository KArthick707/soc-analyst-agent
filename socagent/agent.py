"""Two bounded Claude tool-calling loops sharing one tool belt:

  * triage_alert()  -- given a security alert, gather evidence on its
    indicators and recommend a verdict. The agent never sets the verdict
    itself; fuse_recommendation() maps the evidence trail to one
    deterministically, so a well-worded alert can't talk its way past it.
  * chat_turn()      -- a conversational copilot over a loaded log file. No
    verdict to fuse here (it's assistive, not decision-making), but answers
    must be grounded in search_logs/read_log_lines results, not invented.

Uses a manual agentic loop (not the SDK tool runner) so budget caps -- max
tool calls and total wall-clock -- are enforced on every iteration.
"""

import json
import time

from . import config, tools
from .schemas import (
    PRIORITY_P1_CRITICAL,
    PRIORITY_P2_HIGH,
    PRIORITY_P3_MEDIUM,
    PRIORITY_P4_LOW,
    SIGNAL_MALICIOUS,
    SIGNAL_SUSPICIOUS,
    VERDICT_ESCALATE,
    VERDICT_MONITOR,
    VERDICT_NO_ACTION,
    EvidenceStep,
    Investigation,
    Triage,
)

MAX_TOKENS = 4096

TIER1_SYSTEM_PROMPT = (
    "You are a Tier 1 SOC (Security Operations Center) analyst doing first-pass triage "
    "on a security alert. Your job is speed: decide quickly whether this looks like a "
    "real threat that needs Tier 2's attention, or noise. Use the available tools to "
    "gather corroborating evidence on the alert's indicators: check domain age and DNS "
    "resolution for domain indicators, reverse-DNS and address-space context for IP "
    "indicators. Investigate what's specific to THIS alert rather than running every "
    "tool by rote -- be efficient, you have a limited tool budget.\n\n"
    "You do not decide the final verdict; a separate deterministic step scores the "
    "evidence you gather. When you have enough evidence, stop calling tools and write "
    "a concise analyst summary (2-4 sentences) of what you found and why it matters."
)

TIER2_SYSTEM_PROMPT = (
    "You are a Tier 2 SOC analyst doing a deep-dive investigation on an alert that "
    "Tier 1 has already escalated (or that otherwise warrants close attention). Unlike "
    "a first-pass triage, your job is to correlate ALL of the alert's indicators "
    "together and build a coherent narrative of what likely happened (e.g. initial "
    "access -> execution -> command-and-control -> persistence), not just check "
    "indicators one at a time. Use the available tools generously -- your budget is "
    "larger than Tier 1's specifically so you can check every indicator, not just the "
    "most obvious one, and pull surrounding context from the log if one is loaded.\n\n"
    "You do not decide the final priority or recommended actions yourself; a "
    "deterministic step derives those from the evidence you gather. When you have "
    "enough evidence, stop calling tools and write a 3-6 sentence incident narrative "
    "that connects the evidence into a story an incident responder can act on."
)

CHAT_SYSTEM_PROMPT = (
    "You are a SOC analyst copilot helping a human analyst investigate a loaded log "
    "file and answer questions about it. You have tools to search the log and read "
    "specific line ranges, and to look up domains/IPs that appear in it. Always ground "
    "factual claims about the log's contents in actual search_logs/read_log_lines "
    "results -- never invent log lines, timestamps, or IOC verdicts. If the log "
    "doesn't contain enough information to answer, say so plainly and suggest what to "
    "search for next. Keep answers concise and actionable."
)


class AgentNotConfigured(RuntimeError):
    """Raised when no Anthropic API key is configured."""


def _build_client():
    """Test seam: constructing the Anthropic client."""
    import anthropic

    return anthropic.Anthropic()


def _model_kwargs(model: str) -> dict:
    """Adaptive thinking suits a decision-making agent but 400s on Haiku, so
    enable it only on model families known to support it."""
    if model.lower().startswith(("claude-opus", "claude-sonnet", "claude-fable")):
        return {"thinking": {"type": "adaptive"}}
    return {}


def _alert_context(alert: dict, tier1_context: dict | None = None) -> str:
    indicators = alert.get("indicators", []) or []
    indicator_lines = [f"  - {ind.get('type', '?')}: {ind.get('value', '?')}" for ind in indicators]
    lines = [
        "A security alert needs triage. Here is what's known:",
        "",
        f"- Source: {alert.get('source', 'unknown')}",
        f"- Timestamp: {alert.get('timestamp', 'unknown')}",
        f"- Reported severity: {alert.get('severity', 'unknown')}",
        f"- Title: {alert.get('title', '')}",
        f"- Description: {alert.get('description', '')}",
        "- Indicators:",
        *(indicator_lines or ["  (none provided)"]),
    ]
    if alert.get("raw"):
        lines += ["", "Raw excerpt:", str(alert["raw"])[:1000]]
    if tier1_context:
        lines += [
            "",
            "Tier 1 already triaged this alert and escalated it to you:",
            f"- Tier 1 verdict: {tier1_context.get('recommended_verdict', 'unknown')}",
            f"- Tier 1 summary: {tier1_context.get('agent_summary', '')}",
        ]
    return "\n".join(lines)


def _run_tool_loop(
    client, model: str, system_prompt: str, messages: list, *,
    log_text: str | None = None, max_calls: int | None = None, timeout: float | None = None,
):
    """Drives one bounded tool-calling loop to completion (or budget exhaustion)
    starting from the given message history. Mutates and returns ``messages``
    alongside the evidence trail, tools used, budget, and final assistant text.
    ``max_calls``/``timeout`` default to the Tier 1 config knobs; Tier 2 passes
    its own larger budget explicitly."""
    max_calls = max_calls if max_calls is not None else config.get_max_tool_calls()
    timeout = timeout if timeout is not None else config.get_total_timeout_seconds()
    model_kwargs = _model_kwargs(model)

    evidence: list = []
    tools_used: list = []
    tool_calls = 0
    step_no = 0
    final_text = ""
    stopped_reason = "completed"
    start = time.monotonic()

    for _ in range(max_calls + 3):
        if tool_calls >= max_calls:
            stopped_reason = "max_tool_calls"
            break
        if time.monotonic() - start > timeout:
            stopped_reason = "timeout"
            break

        try:
            response = client.messages.create(
                model=model,
                max_tokens=MAX_TOKENS,
                system=system_prompt,
                tools=tools.TOOL_SCHEMAS,
                messages=messages,
                **model_kwargs,
            )
        except Exception as exc:  # noqa: BLE001 -- surface any SDK/transport error as a stop
            stopped_reason = f"llm_error:{type(exc).__name__}"
            break

        text = "".join(
            getattr(b, "text", "") for b in response.content if getattr(b, "type", None) == "text"
        ).strip()
        if text:
            final_text = text

        messages.append({"role": "assistant", "content": response.content})

        tool_uses = [b for b in response.content if getattr(b, "type", None) == "tool_use"]
        if not tool_uses:
            stopped_reason = "completed"
            break

        results = []
        for block in tool_uses:
            over_budget = tool_calls >= max_calls or (time.monotonic() - start) > timeout
            if over_budget:
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": "Tool budget exceeded; tool not executed.",
                    "is_error": True,
                })
                stopped_reason = "max_tool_calls" if tool_calls >= max_calls else "timeout"
                continue

            finding = tools.execute_tool(block.name, dict(block.input or {}), log_text=log_text)
            tool_calls += 1
            step_no += 1
            tools_used.append(block.name)
            evidence.append(
                EvidenceStep(
                    step=step_no,
                    tool=block.name,
                    tool_input=dict(block.input or {}),
                    finding=finding,
                    signal=finding.get("signal", "neutral"),
                    summary=finding.get("summary", ""),
                ).to_dict()
            )
            results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": json.dumps(finding, default=str),
            })

        messages.append({"role": "user", "content": results})
        if stopped_reason in ("max_tool_calls", "timeout"):
            break

    budget = {
        "tool_calls": tool_calls,
        "max_tool_calls": max_calls,
        "elapsed_ms": int((time.monotonic() - start) * 1000),
        "stopped_reason": stopped_reason,
    }
    return messages, evidence, sorted(set(tools_used)), budget, final_text


def fuse_recommendation(evidence_trail: list) -> str:
    """Deterministically map agent-gathered evidence to a recommended verdict.

    Never returns "confirmed benign" -- only "no_action" when nothing
    escalated. Absence of malicious evidence isn't proof of safety, and the
    cost asymmetry favors caution: a missed escalation costs an analyst a few
    minutes of review; a wrongly-cleared alert costs a real incident going
    unnoticed."""
    malicious = [s for s in evidence_trail if s.get("signal") == SIGNAL_MALICIOUS]
    suspicious = [s for s in evidence_trail if s.get("signal") == SIGNAL_SUSPICIOUS]

    if len(malicious) >= 1:
        return VERDICT_ESCALATE
    if len(suspicious) >= 1:
        return VERDICT_MONITOR
    return VERDICT_NO_ACTION


def triage_alert(alert: dict) -> dict:
    """Tier 1: run the bounded agent loop over a security alert and return a
    Triage dict (escalate / monitor / no_action)."""
    if not config.has_api_key():
        raise AgentNotConfigured(
            "Triage requires an Anthropic API key. Set the ANTHROPIC_API_KEY environment variable."
        )

    client = _build_client()
    model = config.get_model()
    messages = [{"role": "user", "content": _alert_context(alert)}]

    messages, evidence, tools_used, budget, final_text = _run_tool_loop(
        client, model, TIER1_SYSTEM_PROMPT, messages
    )

    if not final_text:
        final_text = (
            " ".join(step.get("summary", "") for step in evidence).strip()
            or "The triage ran but gathered no evidence."
        )

    triage = Triage(
        investigated=True,
        agent_summary=final_text,
        recommended_verdict=fuse_recommendation(evidence),
        evidence_trail=evidence,
        tools_used=tools_used,
        budget=budget,
    )
    return triage.to_dict()


# --------------------------------------------------------------------------- #
# Tier 2: deep investigation of an already-escalated alert
# --------------------------------------------------------------------------- #

_ACTION_TEMPLATES = {
    "whois_domain_age": "Block/deny '{value}' at DNS or web proxy -- WHOIS shows it's likely attacker-registered infrastructure.",
    "dns_lookup": "Isolate the host that queried '{value}'; it resolves into private/non-routable space, consistent with DNS rebinding or internal misdirection.",
}


def fuse_priority_and_actions(evidence_trail: list) -> tuple:
    """Deterministically map Tier 2's evidence trail to a P1-P4 priority and a
    list of concrete next actions. Same philosophy as fuse_recommendation: the
    LLM never sets priority or actions directly, only gathers the evidence
    this reads."""
    malicious_steps = [s for s in evidence_trail if s.get("signal") == SIGNAL_MALICIOUS]
    suspicious_steps = [s for s in evidence_trail if s.get("signal") == SIGNAL_SUSPICIOUS]

    if len(malicious_steps) >= 2:
        priority = PRIORITY_P1_CRITICAL
    elif len(malicious_steps) == 1:
        priority = PRIORITY_P2_HIGH
    elif suspicious_steps:
        priority = PRIORITY_P3_MEDIUM
    else:
        priority = PRIORITY_P4_LOW

    actions: list = []
    for step in malicious_steps:
        tool_input = step.get("tool_input", {}) or {}
        value = tool_input.get("domain") or tool_input.get("ip") or "the indicator"
        template = _ACTION_TEMPLATES.get(step.get("tool"))
        if template:
            actions.append(template.format(value=value))
        else:
            actions.append(f"Manually review the '{step.get('tool')}' finding on {value}; evidence indicates a malicious signal.")

    if not actions:
        if suspicious_steps:
            actions.append("No confirmed-malicious evidence yet -- add the flagged indicator(s) to a watchlist and re-check in 24-48h.")
        else:
            actions.append("No malicious or suspicious evidence found -- likely safe to close as a false positive pending Tier 1 concurrence.")

    seen = set()
    deduped_actions = []
    for action in actions:
        if action not in seen:
            seen.add(action)
            deduped_actions.append(action)

    return priority, deduped_actions


def investigate_incident(alert: dict, tier1_context: dict | None = None) -> dict:
    """Tier 2: deep-dive an alert (optionally with the Tier 1 report that
    escalated it) and return an Investigation dict with a priority ranking
    and recommended containment/remediation actions."""
    if not config.has_api_key():
        raise AgentNotConfigured(
            "Investigation requires an Anthropic API key. Set the ANTHROPIC_API_KEY environment variable."
        )

    client = _build_client()
    model = config.get_model()
    messages = [{"role": "user", "content": _alert_context(alert, tier1_context)}]

    messages, evidence, tools_used, budget, final_text = _run_tool_loop(
        client, model, TIER2_SYSTEM_PROMPT, messages,
        max_calls=config.get_tier2_max_tool_calls(),
        timeout=config.get_tier2_timeout_seconds(),
    )

    if not final_text:
        final_text = (
            " ".join(step.get("summary", "") for step in evidence).strip()
            or "The investigation ran but gathered no evidence."
        )

    priority, actions = fuse_priority_and_actions(evidence)

    investigation = Investigation(
        investigated=True,
        agent_summary=final_text,
        priority=priority,
        recommended_actions=actions,
        evidence_trail=evidence,
        tools_used=tools_used,
        budget=budget,
    )
    return investigation.to_dict()


def chat_turn(question: str, messages: list, log_text: str | None = None) -> dict:
    """Run one turn of the log Q&A copilot. ``messages`` is the running
    conversation history (mutated and returned) so the CLI can keep a REPL."""
    if not config.has_api_key():
        raise AgentNotConfigured(
            "Chat requires an Anthropic API key. Set the ANTHROPIC_API_KEY environment variable."
        )

    client = _build_client()
    model = config.get_model()
    messages.append({"role": "user", "content": question})

    messages, evidence, tools_used, budget, final_text = _run_tool_loop(
        client, model, CHAT_SYSTEM_PROMPT, messages, log_text=log_text
    )

    if not final_text:
        final_text = "I couldn't produce an answer within the tool budget -- try a more specific question."

    return {
        "answer": final_text,
        "messages": messages,
        "evidence_trail": evidence,
        "tools_used": tools_used,
        "budget": budget,
    }
