"""Command-line interface for codex-xray."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import webbrowser
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path

from .demo import create_demo_repo
from .html_report import render_html
from .render import render_human, render_json
from .rules_catalog import RULES, explain
from .scanner import ScanError, scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="codex-xray",
        description="Explain what Codex will load, override, ignore, or leave conditional.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    scan_parser = subcommands.add_parser("scan", help="Scan a repository, directory, or file")
    scan_parser.add_argument("target", nargs="?", default=".")
    scan_parser.add_argument("--include-user", action="store_true")
    scan_parser.add_argument("--profile")
    scan_parser.add_argument("--trust", choices=("auto", "trusted", "untrusted"), default="auto")
    scan_parser.add_argument(
        "-c", dest="overrides", action="append", default=[], metavar="KEY=VALUE"
    )
    scan_parser.add_argument("--format", choices=("human", "json", "html"), default="human")
    scan_parser.add_argument("--output", type=Path)
    scan_parser.add_argument("--open", action="store_true", dest="open_report")
    scan_parser.add_argument(
        "--fail-on", choices=("never", "warning", "error"), default="never"
    )
    demo_parser = subcommands.add_parser("demo", help="Build and scan a fictional Codex repo")
    demo_parser.add_argument("--open", action="store_true", dest="open_report")
    explain_parser = subcommands.add_parser("explain", help="Explain one deterministic rule")
    explain_parser.add_argument("rule_id")
    return parser


def _atomic_write(path: Path, text: str) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.replace(temporary_name, path)
    except BaseException:
        with suppress(OSError):
            os.unlink(temporary_name)
        raise


def _open_html(text: str, output: Path | None = None) -> Path:
    if output is None:
        directory = Path(tempfile.mkdtemp(prefix="codex-xray-"))
        output = directory / "report.html"
    _atomic_write(output, text)
    webbrowser.open(output.resolve().as_uri())
    return output.resolve()


def _threshold_reached(report_severity: str | None, threshold: str) -> bool:
    if threshold == "never" or report_severity is None:
        return False
    rank = {"info": 0, "warning": 1, "error": 2}
    return rank[report_severity] >= rank[threshold]


def _run_scan(args: argparse.Namespace) -> int:
    if args.format == "html" and args.output is None and not args.open_report:
        raise ScanError("HTML output requires --output PATH or --open.")
    if args.open_report and args.format != "html":
        raise ScanError("--open is only valid with --format html.")
    report = scan(
        args.target,
        include_user=args.include_user,
        profile=args.profile,
        trust=args.trust,
        cli_overrides=args.overrides,
    )
    if args.format == "human":
        rendered = render_human(report)
    elif args.format == "json":
        rendered = render_json(report)
    else:
        rendered = render_html(report)

    if args.open_report:
        path = _open_html(rendered, args.output)
        print(f"Opened {path}")
    elif args.output is not None:
        _atomic_write(args.output, rendered)
        print(args.output.resolve())
    else:
        print(rendered)
    severity = report.max_severity.value if report.max_severity else None
    return 1 if _threshold_reached(severity, args.fail_on) else 0


def _run_demo(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="codex-xray-demo-") as temporary:
        target = create_demo_repo(Path(temporary))
        report = scan(target, trust="trusted")
        if args.open_report:
            path = _open_html(render_html(report))
            print(f"Opened fictional demo: {path}")
        else:
            print(render_human(report))
    return 0


def _run_explain(rule_id: str) -> int:
    item = explain(rule_id)
    if item is None:
        print(f"Unknown rule: {rule_id}", file=sys.stderr)
        print("Known rules: " + ", ".join(sorted(RULES)), file=sys.stderr)
        return 2
    print(f"{item.rule_id}: {item.title}\n\n{item.explanation}\n\nFix: {item.remediation}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "demo":
            return _run_demo(args)
        return _run_explain(args.rule_id)
    except (ScanError, OSError, ValueError) as error:
        print(f"codex-xray: {error}", file=sys.stderr)
        return 2
