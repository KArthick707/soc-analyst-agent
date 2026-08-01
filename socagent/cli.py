"""CLI entrypoint: `python -m socagent triage <alert.json>` and
`python -m socagent chat [--log path]`."""

import argparse
import json
import sys

from . import config
from .agent import AgentNotConfigured, chat_turn, triage_alert


def _load_alert(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_log_text(path: str) -> str:
    """Reads a log file capped to config's byte/line limits so a huge log
    can't blow out memory or the model's context window. Keeps the most
    recent lines, since recent activity is usually what an analyst cares
    about first."""
    max_bytes = config.get_max_log_bytes()
    max_lines = config.get_max_log_lines()

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        fh.seek(max(0, size - max_bytes))
        text = fh.read()

    lines = text.splitlines()
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    return "\n".join(lines)


def _print_triage(report: dict) -> None:
    print(f"\nVerdict: {report['recommended_verdict']}")
    print(f"Summary: {report['agent_summary']}\n")
    print(f"Evidence ({len(report['evidence_trail'])} step(s)):")
    for step in report["evidence_trail"]:
        print(f"  [{step['signal']}] {step['tool']}: {step['summary']}")
    budget = report["budget"]
    print(f"\nTool calls: {budget['tool_calls']}/{budget['max_tool_calls']} "
          f"({budget['elapsed_ms']}ms, stopped: {budget['stopped_reason']})")


def cmd_triage(args: argparse.Namespace) -> int:
    alert = _load_alert(args.alert_path)
    try:
        report = triage_alert(alert)
    except AgentNotConfigured as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    _print_triage(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\nWrote {args.out}")
    return 0


def cmd_chat(args: argparse.Namespace) -> int:
    log_text = _load_log_text(args.log) if args.log else None
    if args.log:
        print(f"Loaded {args.log} ({len(log_text.splitlines())} line(s) in context).")
    else:
        print("No log loaded -- pass --log <path> to ground answers in a log file.")

    print("SOC copilot ready. Type a question, or 'exit' to quit.\n")
    messages: list = []
    while True:
        try:
            question = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not question:
            continue
        if question.lower() in ("exit", "quit"):
            return 0

        try:
            result = chat_turn(question, messages, log_text=log_text)
        except AgentNotConfigured as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

        messages = result["messages"]
        print(f"\n{result['answer']}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="socagent", description="SOC analyst agent: alert triage + log Q&A copilot.")
    sub = parser.add_subparsers(dest="command", required=True)

    triage_p = sub.add_parser("triage", help="Investigate a security alert and recommend a verdict.")
    triage_p.add_argument("alert_path", help="Path to a JSON alert file.")
    triage_p.add_argument("--out", help="Write the full triage report as JSON to this path.")
    triage_p.set_defaults(func=cmd_triage)

    chat_p = sub.add_parser("chat", help="Interactive Q&A copilot over a log file.")
    chat_p.add_argument("--log", help="Path to a log file to load into context.")
    chat_p.set_defaults(func=cmd_chat)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
