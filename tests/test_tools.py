from datetime import datetime, timedelta, timezone

from socagent import tools
from socagent.schemas import SIGNAL_BENIGN, SIGNAL_MALICIOUS, SIGNAL_NEUTRAL, SIGNAL_SUSPICIOUS


def test_ip_context_private():
    result = tools.ip_context("192.168.1.10")
    assert result["classification"] == "private"
    assert result["signal"] == SIGNAL_NEUTRAL


def test_ip_context_loopback():
    assert tools.ip_context("127.0.0.1")["classification"] == "loopback"


def test_ip_context_global():
    result = tools.ip_context("8.8.8.8")
    assert result["classification"] == "global"


def test_ip_context_invalid():
    result = tools.ip_context("not-an-ip")
    assert result["classification"] == "invalid"


def test_search_logs_no_log_loaded():
    result = tools.search_logs("error", None)
    assert result["total_matches"] == 0
    assert "No log" in result["summary"]


def test_search_logs_finds_matches():
    log = "line one ok\nERROR: disk full\nline three ok\nWARN error again"
    result = tools.search_logs("error", log)
    assert result["total_matches"] == 2
    assert result["matches"][0]["line"] == 2
    assert result["matches"][1]["line"] == 4


def test_search_logs_caps_matches():
    log = "\n".join(f"error {i}" for i in range(100))
    result = tools.search_logs("error", log)
    assert result["total_matches"] == 100
    assert len(result["matches"]) == tools.MAX_SEARCH_MATCHES


def test_search_logs_falls_back_to_literal_on_bad_regex():
    log = "value (unbalanced paren"
    result = tools.search_logs("(unbalanced", log)
    assert result["total_matches"] == 1


def test_read_log_lines_range():
    log = "\n".join(f"line{i}" for i in range(1, 11))
    result = tools.read_log_lines(3, 4, log)
    assert result["lines"] == ["line3", "line4", "line5", "line6"]
    assert result["total_lines_in_log"] == 10


def test_read_log_lines_no_log_loaded():
    result = tools.read_log_lines(1, 10, None)
    assert result["lines"] == []


def test_read_log_lines_caps_num_lines():
    log = "\n".join(f"line{i}" for i in range(1, 500))
    result = tools.read_log_lines(1, 1000, log)
    assert len(result["lines"]) == tools.MAX_READ_LINES


def test_whois_domain_age_fresh_domain(monkeypatch):
    class FakeRecord:
        creation_date = datetime.now(timezone.utc) - timedelta(days=3)
        registrar = "Fake Registrar"

    monkeypatch.setattr(tools, "_whois_raw", lambda domain: FakeRecord())
    result = tools.whois_domain_age("freshly-registered.example")
    assert result["signal"] == SIGNAL_MALICIOUS
    assert result["age_days"] == 3


def test_whois_domain_age_suspicious_domain(monkeypatch):
    class FakeRecord:
        creation_date = datetime.now(timezone.utc) - timedelta(days=45)
        registrar = "Fake Registrar"

    monkeypatch.setattr(tools, "_whois_raw", lambda domain: FakeRecord())
    result = tools.whois_domain_age("somewhat-fresh.example")
    assert result["signal"] == SIGNAL_SUSPICIOUS


def test_whois_domain_age_established_domain(monkeypatch):
    class FakeRecord:
        creation_date = datetime.now(timezone.utc) - timedelta(days=2000)
        registrar = "Fake Registrar"

    monkeypatch.setattr(tools, "_whois_raw", lambda domain: FakeRecord())
    result = tools.whois_domain_age("old-established.example")
    assert result["signal"] == SIGNAL_BENIGN


def test_whois_domain_age_lookup_failure_is_neutral(monkeypatch):
    def boom(domain):
        raise RuntimeError("network down")

    monkeypatch.setattr(tools, "_whois_raw", boom)
    result = tools.whois_domain_age("example.com")
    assert result["signal"] == SIGNAL_NEUTRAL
    assert result["error"].startswith("whois_failed")


def test_whois_domain_age_rejects_non_domain():
    result = tools.whois_domain_age("8.8.8.8")
    assert result["error"] == "not_a_registrable_domain"


def test_dns_lookup_resolves(monkeypatch):
    monkeypatch.setattr(tools, "_dns_query", lambda domain, rdtype: ["93.184.216.34"])
    result = tools.dns_lookup("example.com")
    assert result["resolves"] is True
    assert result["signal"] == SIGNAL_NEUTRAL


def test_dns_lookup_private_a_record_is_malicious(monkeypatch):
    monkeypatch.setattr(tools, "_dns_query", lambda domain, rdtype: ["10.0.0.5"])
    result = tools.dns_lookup("rebind.example")
    assert result["signal"] == SIGNAL_MALICIOUS


def test_dns_lookup_no_records(monkeypatch):
    def boom(domain, rdtype):
        raise RuntimeError("NXDOMAIN")

    monkeypatch.setattr(tools, "_dns_query", boom)
    result = tools.dns_lookup("doesnotexist.example")
    assert result["resolves"] is False
    assert result["signal"] == SIGNAL_NEUTRAL


def test_reverse_dns_found(monkeypatch):
    monkeypatch.setattr(tools, "_ptr_query", lambda ip: ["host.example.com."])
    result = tools.reverse_dns("8.8.8.8")
    assert result["hostnames"] == ["host.example.com"]
    assert result["signal"] == SIGNAL_NEUTRAL


def test_reverse_dns_invalid_ip():
    result = tools.reverse_dns("not-an-ip")
    assert result["hostnames"] == []


def test_execute_tool_dispatch(monkeypatch):
    monkeypatch.setattr(tools, "_whois_raw", lambda domain: (_ for _ in ()).throw(RuntimeError("x")))
    result = tools.execute_tool("whois_domain_age", {"domain": "example.com"})
    assert result["signal"] == SIGNAL_NEUTRAL


def test_execute_tool_unknown():
    result = tools.execute_tool("not_a_real_tool", {})
    assert result["error"].startswith("unknown_tool")


def test_execute_tool_search_logs_uses_log_text():
    result = tools.execute_tool("search_logs", {"query": "hi"}, log_text="hi there\nbye")
    assert result["total_matches"] == 1
