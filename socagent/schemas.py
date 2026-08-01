"""Shared data shapes: the evidence a tool call produces, and the verdict
vocabulary fuse_recommendation() maps evidence onto."""

from dataclasses import asdict, dataclass, field

SIGNAL_MALICIOUS = "malicious"
SIGNAL_SUSPICIOUS = "suspicious"
SIGNAL_BENIGN = "benign"
SIGNAL_NEUTRAL = "neutral"

VERDICT_ESCALATE = "escalate"   # strong evidence -> hand to a human analyst now
VERDICT_MONITOR = "monitor"     # some signal, not enough to escalate on its own
VERDICT_NO_ACTION = "no_action"  # no malicious/suspicious evidence found

# Tier 2 priority vocabulary -- standard SOC P1-P4 severity ranking, distinct
# from Tier 1's coarser escalate/monitor/no_action since Tier 2 is deciding
# how urgently to respond, not whether to hand off.
PRIORITY_P1_CRITICAL = "P1_critical"
PRIORITY_P2_HIGH = "P2_high"
PRIORITY_P3_MEDIUM = "P3_medium"
PRIORITY_P4_LOW = "P4_low"


@dataclass
class EvidenceStep:
    step: int
    tool: str
    tool_input: dict
    finding: dict
    signal: str
    summary: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Triage:
    """Tier 1 output: fast escalate/monitor/no_action call."""

    investigated: bool
    agent_summary: str
    recommended_verdict: str
    evidence_trail: list = field(default_factory=list)
    tools_used: list = field(default_factory=list)
    budget: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Investigation:
    """Tier 2 output: deeper dive with a priority ranking and concrete
    containment/remediation actions, not just a hand-off decision."""

    investigated: bool
    agent_summary: str
    priority: str
    recommended_actions: list = field(default_factory=list)
    evidence_trail: list = field(default_factory=list)
    tools_used: list = field(default_factory=list)
    budget: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
