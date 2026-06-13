"""Command-line interface.

Thin wiring layer: parse args -> load export -> run engine -> write
reports. All real logic lives in the other modules so this stays trivial
to read and the pipeline stays trivial to test without a shell.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from .config import AnalyzerConfig
from .engine import SecurityEngine
from .parser import ParserError, load_export
from .reporter import write_reports


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iam-analyzer",
        description=(
            "Contextual blast-radius analyzer for AWS IAM exports "
            "(aws iam get-account-authorization-details), tuned for a PCI DSS "
            "payment-processing environment."
        ),
    )
    p.add_argument(
        "--input", "-i", required=True,
        help="Path to the IAM export JSON to analyze.",
    )
    p.add_argument(
        "--output", "-o", default="reports",
        help="Directory to write report.md and findings.json (default: ./reports).",
    )
    p.add_argument(
        "--config", "-c", default=None,
        help="Optional YAML file overriding the analysis context "
             "(sensitive resources, trusted accounts, etc.).",
    )
    p.add_argument(
        "--fail-on", default=None,
        choices=["critical", "high", "medium", "low"],
        help="Exit non-zero if any finding meets/exceeds this severity "
             "(useful in CI/CD gates).",
    )
    return p


def _load_config(path: str | None) -> AnalyzerConfig:
    if not path:
        return AnalyzerConfig()
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return AnalyzerConfig.from_dict(data)


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    try:
        account = load_export(args.input)
        config = _load_config(args.config)
    except ParserError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, yaml.YAMLError) as exc:
        print(f"error: could not load config: {exc}", file=sys.stderr)
        return 2

    findings = SecurityEngine(config).analyze(account.roles, account.managed_policies)
    paths = write_reports(findings, args.output, warnings=account.warnings)

    crit = sum(1 for f in findings if f.severity.label == "Critical")
    high = sum(1 for f in findings if f.severity.label == "High")
    print(f"Analyzed {len(account.roles)} role(s): {len(findings)} finding(s) "
          f"({crit} critical, {high} high).")
    for label, path in paths.items():
        print(f"  {label}: {path}")
    if account.warnings:
        print(f"  {len(account.warnings)} parser warning(s) — see report.")

    if args.fail_on:
        from .models import Severity
        threshold = Severity[args.fail_on.upper()]
        if any(f.severity >= threshold for f in findings):
            print(f"Gate failed: findings at or above {args.fail_on}.", file=sys.stderr)
            return 1
    return 0
