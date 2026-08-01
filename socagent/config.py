"""Environment configuration. Bare os.environ, no settings framework -- every
knob here bounds either cost (LLM calls) or blast radius (lookups), so the
defaults are deliberately conservative."""

import os

DEFAULT_MODEL = "claude-opus-5"


def get_model() -> str:
    return os.environ.get("SOCAGENT_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL


def get_max_tool_calls() -> int:
    """Hard cap on tool calls per Tier 1 triage/chat turn -- bounds LLM
    round-trips and outbound WHOIS/DNS lookups so a crafted alert or log line
    can't steer the agent into unbounded lookups or cost."""
    return _int_env("SOCAGENT_MAX_TOOL_CALLS", 8, minimum=1)


def get_total_timeout_seconds() -> float:
    return _float_env("SOCAGENT_TIMEOUT_SECONDS", 30.0, minimum=1.0)


def get_tier2_max_tool_calls() -> int:
    """Tier 2 investigates alerts Tier 1 already escalated, correlating every
    indicator rather than stopping at the first one -- it gets a larger
    budget than Tier 1 triage, not an unbounded one."""
    return _int_env("SOCAGENT_TIER2_MAX_TOOL_CALLS", 16, minimum=1)


def get_tier2_timeout_seconds() -> float:
    return _float_env("SOCAGENT_TIER2_TIMEOUT_SECONDS", 60.0, minimum=1.0)


def get_whois_timeout_seconds() -> float:
    return _float_env("SOCAGENT_WHOIS_TIMEOUT_SECONDS", 10.0, minimum=1.0)


def get_dns_timeout_seconds() -> float:
    return _float_env("SOCAGENT_DNS_TIMEOUT_SECONDS", 5.0, minimum=1.0)


def get_max_log_bytes() -> int:
    """Cap on how much of a log file is loaded into memory/context at once."""
    return _int_env("SOCAGENT_MAX_LOG_BYTES", 2_000_000, minimum=1000)


def get_max_log_lines() -> int:
    return _int_env("SOCAGENT_MAX_LOG_LINES", 20_000, minimum=100)


def has_api_key() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())


def _int_env(name: str, default: int, *, minimum: int) -> int:
    try:
        return max(minimum, int(os.environ[name]))
    except (KeyError, ValueError):
        return default


def _float_env(name: str, default: float, *, minimum: float) -> float:
    try:
        return max(minimum, float(os.environ[name]))
    except (KeyError, ValueError):
        return default
