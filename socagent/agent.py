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
    SIGNAL_MALICIOUS,
    SIGNAL_SUSPICIOUS,
    VERDICT_ESCALATE,
    VERDICT_MONITOR,
    VERDICT_NO_ACTION,
    EvidenceStep,
    Triage,
)

MAX_TOKENS = 4096

TRIAGE_SYSTEM_PROMPT = (
    "You are a SOC (Security Operations Center) analyst assistant investigating a "
    "security alert. Use the available tools to gather corroborating evidence on the "
    "alert's indicators: check domain age and DNS resolution for domain indicators, "
    "reverse-DNS and address-space context for IP indicators. Investigate what's "
    "specific to THIS alert rather than running every tool by rote -- be efficient, "
    "you have a limited tool budget.\n\n"
    "You do not decide the final verdict; a separate deterministic step scores the "
    "evidence you gather. When you have enough evidence, stop calling tools and write "
    "a concise analyst summary (2-4 sentences) of what you found and why it matters."
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


def _alert_context(alert: dict) -> str:
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
    return "\n".join(lines)


def _run_tool_loop(client, model: str, system_prompt: str, messages: list, *, log_text: str | None = None):
    """Drives one bounded tool-calling loop to completion (or budget exhaustion)
    starting from the given message history. Mutates and returns ``messages``
    alongside the evidence trail, tools used, budget, and final assistant text."""
    max_calls = config.get_max_tool_calls()
    timeout = config.get_total_timeout_seconds()
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
    """Run the bounded agent loop over a security alert and return a Triage dict."""
    if not config.has_api_key():
        raise AgentNotConfigured(
            "Triage requires an Anthropic API key. Set the ANTHROPIC_API_KEY environment variable."
        )

    client = _build_client()
    model = config.get_model()
    messages = [{"role": "user", "content": _alert_context(alert)}]

    messages, evidence, tools_used, budget, final_text = _run_tool_loop(
        client, model, TRIAGE_SYSTEM_PROMPT, messages
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
