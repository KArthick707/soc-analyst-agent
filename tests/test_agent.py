from socagent.agent import fuse_priority_and_actions, fuse_recommendation
from socagent.schemas import (
    PRIORITY_P1_CRITICAL,
    PRIORITY_P2_HIGH,
    PRIORITY_P3_MEDIUM,
    PRIORITY_P4_LOW,
    SIGNAL_BENIGN,
    SIGNAL_MALICIOUS,
    SIGNAL_NEUTRAL,
    SIGNAL_SUSPICIOUS,
    VERDICT_ESCALATE,
    VERDICT_MONITOR,
    VERDICT_NO_ACTION,
)


def _step(signal, tool="dns_lookup", tool_input=None):
    return {"signal": signal, "tool": tool, "tool_input": tool_input or {"domain": "evil.example"}}


def test_fuse_no_evidence_is_no_action():
    assert fuse_recommendation([]) == VERDICT_NO_ACTION


def test_fuse_all_benign_is_no_action():
    assert fuse_recommendation([_step(SIGNAL_BENIGN), _step(SIGNAL_NEUTRAL)]) == VERDICT_NO_ACTION


def test_fuse_suspicious_only_is_monitor():
    assert fuse_recommendation([_step(SIGNAL_SUSPICIOUS), _step(SIGNAL_BENIGN)]) == VERDICT_MONITOR


def test_fuse_any_malicious_is_escalate():
    assert fuse_recommendation([_step(SIGNAL_SUSPICIOUS), _step(SIGNAL_MALICIOUS)]) == VERDICT_ESCALATE


def test_fuse_priority_no_evidence_is_p4_with_false_positive_action():
    priority, actions = fuse_priority_and_actions([])
    assert priority == PRIORITY_P4_LOW
    assert "false positive" in actions[0]


def test_fuse_priority_suspicious_only_is_p3_with_watchlist_action():
    priority, actions = fuse_priority_and_actions([_step(SIGNAL_SUSPICIOUS)])
    assert priority == PRIORITY_P3_MEDIUM
    assert "watchlist" in actions[0]


def test_fuse_priority_one_malicious_is_p2_with_specific_action():
    priority, actions = fuse_priority_and_actions(
        [_step(SIGNAL_MALICIOUS, tool="whois_domain_age", tool_input={"domain": "evil.example"})]
    )
    assert priority == PRIORITY_P2_HIGH
    assert "evil.example" in actions[0]


def test_fuse_priority_two_malicious_is_p1():
    evidence = [
        _step(SIGNAL_MALICIOUS, tool="whois_domain_age", tool_input={"domain": "evil.example"}),
        _step(SIGNAL_MALICIOUS, tool="dns_lookup", tool_input={"domain": "evil.example"}),
    ]
    priority, actions = fuse_priority_and_actions(evidence)
    assert priority == PRIORITY_P1_CRITICAL
    assert len(actions) == 2


def test_fuse_priority_dedupes_repeated_actions():
    evidence = [
        _step(SIGNAL_MALICIOUS, tool="whois_domain_age", tool_input={"domain": "evil.example"}),
        _step(SIGNAL_MALICIOUS, tool="whois_domain_age", tool_input={"domain": "evil.example"}),
    ]
    _, actions = fuse_priority_and_actions(evidence)
    assert len(actions) == 1


def test_fuse_priority_unknown_tool_falls_back_to_generic_action():
    priority, actions = fuse_priority_and_actions(
        [_step(SIGNAL_MALICIOUS, tool="reverse_dns", tool_input={"ip": "1.2.3.4"})]
    )
    assert priority == PRIORITY_P2_HIGH
    assert "reverse_dns" in actions[0]
