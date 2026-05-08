"""CLI — `policy-guard check`, `policy-guard audit`, `policy-guard validate`."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from llm_policy_guard.audit import AuditLog
from llm_policy_guard.engine import PolicyBlockedError, PolicyEngine
from llm_policy_guard.loader import load_policy

app = typer.Typer(name="policy-guard", help="Policy-as-code enforcement for LLM applications.")
console = Console(stderr=True)


@app.command()
def check(
    policy: Path = typer.Argument(..., help="Path to policy YAML file"),
    text: Optional[str] = typer.Option(None, "-t", "--text", help="Text to check (or pipe via stdin)"),
    direction: str = typer.Option("input", "-d", "--direction", help="Content direction: input | output | both"),
    audit_file: Optional[Path] = typer.Option(None, "--audit", help="Append audit entry to this file"),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Only exit code, no output"),
) -> None:
    """Check text against a policy file."""
    if text is None:
        if not sys.stdin.isatty():
            text = sys.stdin.read()
        else:
            console.print("[red]Provide text via -t or stdin[/red]")
            raise typer.Exit(2)

    config = load_policy(policy)
    audit_log = AuditLog(audit_file) if audit_file else None
    engine = PolicyEngine(config, audit_log=audit_log, raise_on_block=False)

    from llm_policy_guard.models import ContentDirection
    try:
        dir_enum = ContentDirection(direction)
    except ValueError:
        console.print(f"[red]Invalid direction: {direction}[/red]")
        raise typer.Exit(2)

    result = engine.check(text, dir_enum)
    violations = []
    for checker in engine._checkers:
        _, vs = checker.check(text, dir_enum)
        violations.extend(vs)

    if not quiet:
        if violations:
            console.print(f"[red]BLOCKED — {len(violations)} violation(s)[/red]")
            for v in violations:
                console.print(f"  [{v.severity}] {v.rule_name}: {v.message}")
                if v.matched_text:
                    console.print(f"    Matched: [dim]{v.matched_text}[/dim]")
        else:
            console.print("[green]PASSED — no violations[/green]")

    raise typer.Exit(1 if violations else 0)


@app.command()
def validate(
    policy: Path = typer.Argument(..., help="Path to policy YAML file"),
) -> None:
    """Validate a policy YAML file for correctness."""
    try:
        config = load_policy(policy)
        console.print(f"[green]Valid policy:[/green] {config.name} v{config.version}")
        console.print(f"  {len(config.rules)} rules ({len(config.enabled_rules)} enabled)")
        for rule in config.rules:
            status = "[green]on[/green]" if rule.enabled else "[dim]off[/dim]"
            console.print(f"  [{status}] {rule.id}: {rule.name} ({rule.category.value}, {rule.action.value})")
    except Exception as e:
        console.print(f"[red]Invalid policy: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def audit(
    audit_file: Path = typer.Argument(..., help="Path to audit log JSONL file"),
    top: int = typer.Option(10, "--top", help="Show top N rules by violation count"),
) -> None:
    """Display audit log summary."""
    if not audit_file.exists():
        console.print(f"[red]Audit file not found: {audit_file}[/red]")
        raise typer.Exit(1)

    log = AuditLog.from_file(audit_file)
    summary = log.summary()

    table = Table(title="Audit Summary", show_header=True)
    table.add_column("Metric")
    table.add_column("Value", justify="right")

    table.add_row("Total checks", str(summary["total_checks"]))
    table.add_row("Passed", str(summary["passed"]))
    table.add_row("Blocked", str(summary["blocked"]))
    table.add_row("Block rate", summary["block_rate"])
    table.add_row("Total violations", str(summary["total_violations"]))

    console.print(table)

    if summary["top_rules"]:
        rule_table = Table(title="Top Violated Rules", show_header=True)
        rule_table.add_column("Rule ID")
        rule_table.add_column("Violations", justify="right")
        for rule_id, count in summary["top_rules"][:top]:
            rule_table.add_row(rule_id, str(count))
        console.print(rule_table)


@app.command()
def version() -> None:
    """Print the policy-guard version."""
    from llm_policy_guard import __version__
    typer.echo(f"llm-policy-guard {__version__}")


if __name__ == "__main__":
    app()
