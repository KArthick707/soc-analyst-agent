from socagent.agent import fuse_recommendation
from socagent.schemas import (
    SIGNAL_BENIGN,
    SIGNAL_MALICIOUS,
    SIGNAL_NEUTRAL,
    SIGNAL_SUSPICIOUS,
    VERDICT_ESCALATE,
    VERDICT_MONITOR,
    VERDICT_NO_ACTION,
)


def _step(signal):
    return {"signal": signal}


def test_fuse_no_evidence_is_no_action():
    assert fuse_recommendation([]) == VERDICT_NO_ACTION


def test_fuse_all_benign_is_no_action():
    assert fuse_recommendation([_step(SIGNAL_BENIGN), _step(SIGNAL_NEUTRAL)]) == VERDICT_NO_ACTION


def test_fuse_suspicious_only_is_monitor():
    assert fuse_recommendation([_step(SIGNAL_SUSPICIOUS), _step(SIGNAL_BENIGN)]) == VERDICT_MONITOR


def test_fuse_any_malicious_is_escalate():
    assert fuse_recommendation([_step(SIGNAL_SUSPICIOUS), _step(SIGNAL_MALICIOUS)]) == VERDICT_ESCALATE
