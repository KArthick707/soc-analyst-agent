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
    investigated: bool
    agent_summary: str
    recommended_verdict: str
    evidence_trail: list = field(default_factory=list)
    tools_used: list = field(default_factory=list)
    budget: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
