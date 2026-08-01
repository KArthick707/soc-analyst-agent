"""The agent's tool belt: deterministic functions the LLM can call, plus their
Anthropic tool schemas and a dispatcher.

Design notes (mirrors the pattern used in this author's PhishScope investigator
agent):
  * Every tool returns a plain dict that always carries a ``signal`` (one of
    SIGNAL_*) and a one-line ``summary``. The *tool* decides the signal, never
    the LLM -- so the evidence trail the agent assembles is verifiable.
  * whois_domain_age / dns_lookup do real outbound lookups (WHOIS, DNS) and can
    fail closed to a neutral signal; they never raise into the agent loop.
  * reverse_dns and ip_context are informational only (always neutral) -- there
    is no reputation database behind them, so they must not be dressed up as a
    verdict.
  * search_logs / read_log_lines do no network I/O; they operate on whatever
    log text the caller loaded into memory and are how the chat copilot grounds
    its answers instead of inventing log content.
"""

import ipaddress
import re
from datetime import datetime, timezone

from .schemas import SIGNAL_BENIGN, SIGNAL_MALICIOUS, SIGNAL_NEUTRAL, SIGNAL_SUSPICIOUS

MAX_SEARCH_MATCHES = 50
MAX_READ_LINES = 200


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# WHOIS domain age
# --------------------------------------------------------------------------- #

def _whois_raw(domain: str):
    """Test seam: the actual WHOIS call. python-whois parsing is flaky per-TLD,
    so callers wrap this in try/except and degrade to a neutral 'unknown'
    signal rather than crash."""
    import whois
    from . import config

    return whois.whois(domain, timeout=int(config.get_whois_timeout_seconds()))


def _earliest_datetime(value) -> datetime | None:
    """python-whois returns creation_date as a datetime, a list of them, or
    None. Normalize to the earliest timezone-aware (UTC) datetime; naive
    values are assumed to already be UTC."""
    if value is None:
        return None
    candidates = value if isinstance(value, (list, tuple)) else [value]
    parsed = []
    for item in candidates:
        if isinstance(item, datetime):
            parsed.append(item.astimezone(timezone.utc) if item.tzinfo else item.replace(tzinfo=timezone.utc))
    return min(parsed) if parsed else None


def whois_domain_age(domain: str) -> dict:
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain or _is_ip(domain) or "." not in domain:
        return {
            "domain": domain, "age_days": None, "created": None, "registrar": None,
            "error": "not_a_registrable_domain", "signal": SIGNAL_NEUTRAL,
            "summary": f"'{domain}' is not a domain that can be aged via WHOIS.",
        }

    try:
        record = _whois_raw(domain)
    except Exception as exc:  # noqa: BLE001 -- WHOIS libraries raise many types
        return {
            "domain": domain, "age_days": None, "created": None, "registrar": None,
            "error": f"whois_failed:{type(exc).__name__}", "signal": SIGNAL_NEUTRAL,
            "summary": f"WHOIS lookup for '{domain}' failed; age unknown.",
        }

    created = _earliest_datetime(getattr(record, "creation_date", None))
    registrar = getattr(record, "registrar", None)

    if created is None:
        return {
            "domain": domain, "age_days": None, "created": None, "registrar": registrar,
            "error": "no_creation_date", "signal": SIGNAL_NEUTRAL,
            "summary": f"WHOIS returned no creation date for '{domain}'; age unknown.",
        }

    age_days = max(0, (datetime.now(timezone.utc) - created).days)
    if age_days < 30:
        signal = SIGNAL_MALICIOUS
        summary = (
            f"'{domain}' was registered only {age_days} day(s) ago. Freshly-registered "
            "domains are a well-known heuristic for attacker-controlled infrastructure "
            "(C2, phishing, staging) -- worth corroborating with other evidence."
        )
    elif age_days < 90:
        signal = SIGNAL_SUSPICIOUS
        summary = f"'{domain}' was registered {age_days} day(s) ago -- moderately fresh, worth a second look but not conclusive on its own."
    elif age_days >= 180:
        signal = SIGNAL_BENIGN
        summary = f"'{domain}' has been registered for {age_days} day(s), consistent with established infrastructure."
    else:
        signal = SIGNAL_NEUTRAL
        summary = f"'{domain}' is {age_days} day(s) old -- neither clearly fresh nor clearly established."

    return {
        "domain": domain, "age_days": age_days, "created": created.isoformat(),
        "registrar": registrar, "error": None, "signal": signal, "summary": summary,
    }


# --------------------------------------------------------------------------- #
# DNS lookup
# --------------------------------------------------------------------------- #

def _dns_query(domain: str, rdtype: str):
    """Test seam: a single DNS query. Isolated so tests never hit real DNS."""
    import dns.resolver
    from . import config

    resolver = dns.resolver.Resolver()
    resolver.lifetime = config.get_dns_timeout_seconds()
    return resolver.resolve(domain, rdtype)


def dns_lookup(domain: str) -> dict:
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain or _is_ip(domain) or "." not in domain:
        return {
            "domain": domain, "resolves": False, "a_records": [],
            "signal": SIGNAL_NEUTRAL, "summary": f"'{domain}' is not a resolvable domain.",
        }

    a_records: list[str] = []
    try:
        a_records = [str(r) for r in _dns_query(domain, "A")]
    except Exception:  # noqa: BLE001 -- NXDOMAIN, NoAnswer, timeouts, etc.
        pass

    resolves = bool(a_records)
    private_a = [ip for ip in a_records if _is_ip(ip) and not ipaddress.ip_address(ip).is_global]

    if private_a:
        signal = SIGNAL_MALICIOUS
        summary = (
            f"'{domain}' resolves into private/non-routable IP space ({', '.join(private_a)}) -- "
            "abnormal for a domain that should point at public infrastructure, and a pattern "
            "seen in DNS-rebinding attacks."
        )
    elif resolves:
        signal = SIGNAL_NEUTRAL
        summary = f"'{domain}' resolves to {', '.join(a_records)}."
    else:
        signal = SIGNAL_NEUTRAL
        summary = f"'{domain}' does not currently resolve to an A record."

    return {
        "domain": domain, "resolves": resolves, "a_records": a_records,
        "signal": signal, "summary": summary,
    }


# --------------------------------------------------------------------------- #
# Reverse DNS + IP context (no network beyond the PTR lookup; both informational)
# --------------------------------------------------------------------------- #

def _ptr_query(ip: str):
    import dns.reversename
    import dns.resolver

    rev_name = dns.reversename.from_address(ip)
    return dns.resolver.resolve(rev_name, "PTR")


def reverse_dns(ip: str) -> dict:
    ip = (ip or "").strip()
    if not _is_ip(ip):
        return {
            "ip": ip, "hostnames": [], "signal": SIGNAL_NEUTRAL,
            "summary": f"'{ip}' is not a valid IP address.",
        }
    try:
        hostnames = [str(r).rstrip(".") for r in _ptr_query(ip)]
    except Exception:  # noqa: BLE001
        hostnames = []

    summary = (
        f"'{ip}' resolves via PTR to {', '.join(hostnames)}." if hostnames
        else f"'{ip}' has no PTR record."
    )
    return {"ip": ip, "hostnames": hostnames, "signal": SIGNAL_NEUTRAL, "summary": summary}


def ip_context(ip: str) -> dict:
    """Classify an IP's address space (private/loopback/link-local/reserved/
    global) using stdlib ipaddress only -- no network call, no reputation
    claim. Always neutral: whether an IP is internal or public is context for
    the analyst, not by itself a verdict."""
    ip = (ip or "").strip()
    if not _is_ip(ip):
        return {"ip": ip, "classification": "invalid", "signal": SIGNAL_NEUTRAL,
                 "summary": f"'{ip}' is not a valid IP address."}

    addr = ipaddress.ip_address(ip)
    if addr.is_loopback:
        classification = "loopback"
    elif addr.is_link_local:
        classification = "link_local"
    elif addr.is_private:
        classification = "private"
    elif addr.is_reserved:
        classification = "reserved"
    elif addr.is_multicast:
        classification = "multicast"
    elif addr.is_global:
        classification = "global"
    else:
        classification = "other"

    summary = {
        "loopback": f"'{ip}' is a loopback address (this host).",
        "link_local": f"'{ip}' is a link-local address (same-segment only).",
        "private": f"'{ip}' is in private/internal address space (RFC1918) -- likely an internal host, not external attacker infrastructure, unless spoofed.",
        "reserved": f"'{ip}' is in a reserved/special-use range.",
        "multicast": f"'{ip}' is a multicast address.",
        "global": f"'{ip}' is a public, globally-routable address.",
        "other": f"'{ip}' does not fit a standard address-space category.",
    }[classification]

    return {"ip": ip, "classification": classification, "signal": SIGNAL_NEUTRAL, "summary": summary}


# --------------------------------------------------------------------------- #
# Log search / read (no network; operate on caller-supplied log_text)
# --------------------------------------------------------------------------- #

def search_logs(query: str, log_text: str | None) -> dict:
    if not log_text:
        return {"query": query, "matches": [], "total_matches": 0, "signal": SIGNAL_NEUTRAL,
                 "summary": "No log is currently loaded."}
    if not query:
        return {"query": query, "matches": [], "total_matches": 0, "signal": SIGNAL_NEUTRAL,
                 "summary": "Empty query."}

    try:
        pattern = re.compile(query, re.IGNORECASE)
    except re.error:
        pattern = re.compile(re.escape(query), re.IGNORECASE)

    matches = []
    total = 0
    for i, line in enumerate(log_text.splitlines(), start=1):
        if pattern.search(line):
            total += 1
            if len(matches) < MAX_SEARCH_MATCHES:
                matches.append({"line": i, "text": line})

    summary = (
        f"Found {total} matching line(s) for '{query}'"
        + (f" (showing first {MAX_SEARCH_MATCHES})" if total > MAX_SEARCH_MATCHES else "")
        + "." if total else f"No lines matched '{query}'."
    )
    return {"query": query, "matches": matches, "total_matches": total,
            "signal": SIGNAL_NEUTRAL, "summary": summary}


def read_log_lines(start_line: int, num_lines: int, log_text: str | None) -> dict:
    if not log_text:
        return {"start_line": start_line, "lines": [], "signal": SIGNAL_NEUTRAL,
                 "summary": "No log is currently loaded."}

    all_lines = log_text.splitlines()
    start_line = max(1, int(start_line or 1))
    num_lines = max(1, min(int(num_lines or 50), MAX_READ_LINES))
    slice_ = all_lines[start_line - 1: start_line - 1 + num_lines]

    return {
        "start_line": start_line, "lines": slice_, "total_lines_in_log": len(all_lines),
        "signal": SIGNAL_NEUTRAL,
        "summary": f"Read {len(slice_)} line(s) starting at line {start_line} (log has {len(all_lines)} total).",
    }


# --------------------------------------------------------------------------- #
# Anthropic tool schemas + dispatch
# --------------------------------------------------------------------------- #

TOOL_SCHEMAS = [
    {
        "name": "whois_domain_age",
        "description": (
            "Look up how long ago a domain was registered via WHOIS. Call this for any "
            "domain indicator in the alert -- domains registered within the last few weeks "
            "are a well-known heuristic for attacker-controlled infrastructure."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "A registrable domain, e.g. 'example.com' (no scheme, no path)."}},
            "required": ["domain"],
        },
    },
    {
        "name": "dns_lookup",
        "description": (
            "Resolve a domain's A records. Call this to check whether a domain actually "
            "resolves and whether it resolves into private/non-routable IP space (a "
            "DNS-rebinding pattern)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "A registrable domain, e.g. 'example.com'."}},
            "required": ["domain"],
        },
    },
    {
        "name": "reverse_dns",
        "description": "Look up the PTR (reverse DNS) hostname(s) for an IP address. Informational only.",
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "An IPv4 or IPv6 address."}},
            "required": ["ip"],
        },
    },
    {
        "name": "ip_context",
        "description": (
            "Classify an IP's address space -- private/internal, loopback, link-local, "
            "reserved, or public/global. No network call, no reputation claim; use this to "
            "tell whether an IP indicator is even capable of being external attacker "
            "infrastructure."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"ip": {"type": "string", "description": "An IPv4 or IPv6 address."}},
            "required": ["ip"],
        },
    },
    {
        "name": "search_logs",
        "description": (
            "Search the currently loaded log for lines matching a substring or regex "
            "pattern (case-insensitive). Use this to find specific events, IPs, "
            "usernames, or error codes -- never guess what's in the log without "
            "searching it first. Returns up to 50 matching lines with line numbers."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "Substring or regex to search for."}},
            "required": ["query"],
        },
    },
    {
        "name": "read_log_lines",
        "description": (
            "Read a contiguous range of lines from the currently loaded log by line "
            "number, e.g. to see the context surrounding a match found via search_logs."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "start_line": {"type": "integer", "description": "1-indexed line number to start reading from."},
                "num_lines": {"type": "integer", "description": "How many lines to read (max 200)."},
            },
            "required": ["start_line"],
        },
    },
]


def execute_tool(name: str, tool_input: dict, *, log_text: str | None = None) -> dict:
    """Route a tool_use call from the agent to the matching deterministic tool.
    Always returns a dict carrying ``signal`` and ``summary``."""
    tool_input = tool_input or {}
    if name == "whois_domain_age":
        return whois_domain_age(tool_input.get("domain", ""))
    if name == "dns_lookup":
        return dns_lookup(tool_input.get("domain", ""))
    if name == "reverse_dns":
        return reverse_dns(tool_input.get("ip", ""))
    if name == "ip_context":
        return ip_context(tool_input.get("ip", ""))
    if name == "search_logs":
        return search_logs(tool_input.get("query", ""), log_text)
    if name == "read_log_lines":
        return read_log_lines(tool_input.get("start_line", 1), tool_input.get("num_lines", 50), log_text)
    return {"error": f"unknown_tool:{name}", "signal": SIGNAL_NEUTRAL, "summary": f"Unknown tool '{name}'."}
