"""Command-line interface.

Ties the components together and enforces the operational safety flow:
scope config is mandatory, a dry-run preview is the default first action, and
live scanning requires an explicit flag. Nothing here should let you skip the
authorization gate.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.table import Table

from aisploit_recon.config.scope import ScopeConfig
from aisploit_recon.config.settings import load_settings
from aisploit_recon.core.auth import AuthCapture, AuthCaptureError, save_auth_state
from aisploit_recon.core.models import CampaignResult
from aisploit_recon.core.scheduler import Campaign
from aisploit_recon.core.scope_guard import ScopeGuard, ScopeViolation
from aisploit_recon.core.session import RateLimiter
from aisploit_recon.core.ssrf_guard import SSRFViolation, check_destination
from aisploit_recon.detection.llm_judge import AnthropicJudgeBackend, LLMJudge
from aisploit_recon.detection.pipeline import DetectionPipeline
from aisploit_recon.evidence.store import EvidenceStore
from aisploit_recon.payloads.models import Payload
from aisploit_recon.payloads.registry import PayloadRegistry
from aisploit_recon.reporting.export import (
    diff_runs,
    export_finding,
)
from aisploit_recon.reporting.generator import ReportGenerator
from aisploit_recon.transport.http_driver import HttpConfig, HttpDriver
from aisploit_recon.transport.playwright_driver import PlaywrightDriver
from aisploit_recon.utils.logging import configure_logging

app = typer.Typer(add_completion=False, help="Authorized LLM security scanner.")
console = Console()

_DEFAULT_LIBRARY = Path(__file__).parent / "payloads" / "library"


def _load_scope(path: Path) -> ScopeConfig:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        console.print(f"[bold red]ERROR:[/] Scope file not found: {path}")
        raise typer.Exit(code=1) from None
    except yaml.YAMLError as exc:
        console.print(f"[bold red]ERROR:[/] Invalid YAML in scope file {path}:\n{exc}")
        raise typer.Exit(code=1) from exc
    try:
        return ScopeConfig.model_validate(data)
    except Exception as exc:
        console.print(f"[bold red]ERROR:[/] Invalid scope config in {path}:\n{exc}")
        raise typer.Exit(code=1) from exc


def _build_pipeline(judge: bool) -> DetectionPipeline:
    settings = load_settings()
    if judge and settings.judge_enabled and settings.anthropic_api_key:
        backend = AnthropicJudgeBackend(settings.anthropic_api_key, settings.judge_model)
        return DetectionPipeline(llm_judge=LLMJudge(backend))
    return DetectionPipeline(llm_judge=None)


def _build_transport(
    transport: str, transport_config: Path, evidence_dir: Path
) -> HttpDriver | PlaywrightDriver:
    try:
        cfg = json.loads(transport_config.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise typer.BadParameter(f"Transport config not found: {transport_config}") from None
    except json.JSONDecodeError as exc:
        raise typer.BadParameter(f"Invalid JSON in transport config: {exc}") from exc
    try:
        if transport == "http":
            return HttpDriver(
                HttpConfig(
                    method=cfg.get("method", "POST"),
                    body_template=cfg.get("body_template"),
                    response_path=cfg.get("response_path", "response"),
                    headers=cfg.get("headers"),
                    timeout_s=cfg.get("timeout_s", 30.0),
                ),
                storage_headers=cfg.get("auth_headers"),
            )
        if transport == "playwright":
            try:
                from aisploit_recon.transport.playwright_driver import PlaywrightConfig
            except ImportError as exc:
                raise typer.BadParameter(
                    "Playwright transport requires the [browser] extra: "
                    "pip install 'aisploit-recon[browser]'"
                ) from exc
            return PlaywrightDriver(
                PlaywrightConfig(
                    input_selector=cfg["input_selector"],
                    submit_selector=cfg["submit_selector"],
                    response_selector=cfg["response_selector"],
                    response_timeout_ms=cfg.get("response_timeout_ms", 30_000),
                    headless=cfg.get("headless", True),
                    evidence_dir=evidence_dir,
                ),
                storage_state=cfg.get("storage_state"),
            )
        raise typer.BadParameter(f"Unknown transport: {transport}")
    except KeyError as exc:
        raise typer.BadParameter(
            f"Missing required key in transport config: {exc}"
        ) from exc


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL of the AI feature"),
    scope: Path = typer.Option(..., "--scope", help="Path to scope YAML (required)"),
    transport: str = typer.Option("http", "--transport", help="http | playwright"),
    transport_config: Path = typer.Option(..., "--transport-config", help="Transport JSON config"),
    category: str | None = typer.Option(None, "--category", help="Filter by payload category"),
    judge: bool = typer.Option(False, "--judge", help="Enable optional LLM judge (sends data out)"),
    live: bool = typer.Option(False, "--live", help="Actually send probes (default is dry-run)"),
    out: Path = typer.Option(Path("./reports"), "--out", help="Report output directory"),
    fail_on: str = typer.Option(
        "", "--fail-on",
        help="CI-gate: fail (exit 1) if any finding >= this severity "
             "(critical|high|medium|low|info)",
    ),
) -> None:
    """Scan an AUTHORIZED target for LLM security weaknesses."""
    settings = load_settings()
    configure_logging(settings.log_level, settings.log_json)

    scope_cfg = _load_scope(scope)
    registry = PayloadRegistry.from_directory(_DEFAULT_LIBRARY)

    payloads = registry.enabled()
    if category:
        from aisploit_recon.payloads.models import PayloadCategory

        payloads = [p for p in payloads if p.category is PayloadCategory(category)]

    rate = RateLimiter(scope_cfg.rules.max_requests_per_minute)
    pipeline = _build_pipeline(judge)
    driver = _build_transport(transport, transport_config, settings.evidence_dir)

    try:
        guard = ScopeGuard(scope_cfg)
        check_destination(
            target,
            allow_private=scope_cfg.rules.allow_private_destinations,
        )
        campaign = Campaign(
            target_url=target,
            transport=driver,
            pipeline=pipeline,
            scope_guard=guard,
            rate_limiter=rate,
            max_concurrent=scope_cfg.rules.max_concurrent,
            baseline_diff=scope_cfg.rules.baseline_diff,
            confirm_trials=scope_cfg.rules.confirm_trials,
            confirm_policy=scope_cfg.rules.confirm_policy,
        )

        if not live:
            _dry_run(campaign, payloads, target)
            return
        run_id = uuid.uuid4().hex[:12]
        result = asyncio.run(campaign.run(payloads))

        store = EvidenceStore(settings.db_path)
        for f in result.findings:
            store.record_finding(run_id, f)

        # CI-gate evaluation (D5b).
        if fail_on:
            from aisploit_recon.reporting.export import ci_gate, parse_fail_on

            threshold = parse_fail_on(fail_on)
            passed, triggers = ci_gate(store, run_id, threshold)
            store.close()

            reporter = ReportGenerator(scope_cfg, redact_secrets=True)
            outputs = reporter.write_all(result, run_id, out)
            _print_summary(result, outputs)

            if not passed:
                console.print(
                    f"\n[bold red]CI-GATE FAILED[/] — {len(triggers)} finding(s) "
                    f"≥ {fail_on} severity:"
                )
                for t in triggers:
                    console.print(
                        f"  • {t['payload_id']} ({t['severity']}) — {t['target_url']}"
                    )
                raise typer.Exit(code=1)
            else:
                console.print(
                    f"\n[bold green]CI-GATE PASSED[/] — no findings ≥ {fail_on}."
                )
        else:
            store.close()
            reporter = ReportGenerator(scope_cfg, redact_secrets=True)
            outputs = reporter.write_all(result, run_id, out)
            _print_summary(result, outputs)
    except ScopeViolation as exc:
        console.print(f"[bold red]SCOPE VIOLATION:[/] {exc}")
        raise typer.Exit(code=2) from exc
    except SSRFViolation as exc:
        console.print(f"[bold red]SSRF BLOCKED:[/] {exc}")
        raise typer.Exit(code=2) from exc


def _dry_run(campaign: Campaign, payloads: list[Payload], target: str) -> None:
    planned = campaign.plan(payloads)
    console.print(f"[bold yellow]DRY RUN[/] — {len(planned)} probes would be sent to {target}\n")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Payload ID")
    table.add_column("Preview (first line)")
    for p in planned:
        first_line = p.rendered_text.strip().splitlines()[0] if p.rendered_text.strip() else ""
        table.add_row(p.payload_id, first_line[:80])
    console.print(table)
    console.print("\n[dim]Re-run with [bold]--live[/bold] to send probes.[/dim]")


def _print_summary(result: CampaignResult, outputs: dict[str, Path]) -> None:
    console.print(
        f"\n[bold]Scan complete[/] — probes: {result.total_probes}, "
        f"vulnerable: [red]{result.vulnerable_count}[/], "
        f"inconclusive: [yellow]{result.inconclusive_count}[/], "
        f"errors: {result.errors}"
    )
    for fmt, path in outputs.items():
        console.print(f"  {fmt:>9}: {path}")


@app.command()
def payloads() -> None:
    """List available payloads in the built-in library."""
    registry = PayloadRegistry.from_directory(_DEFAULT_LIBRARY)
    table = Table(show_header=True, header_style="bold")
    table.add_column("ID")
    table.add_column("Category")
    table.add_column("Detection")
    table.add_column("Sev")
    table.add_column("Name")
    for p in registry.all():
        table.add_row(p.id, p.category.value, p.detection.value, str(p.severity_base), p.name)
    console.print(table)


@app.command()
def purge(
    days: int = typer.Option(
        0, "--days",
        help="Override evidence_retention_days from settings (0 = use settings)",
    ),
) -> None:
    """Purge evidence findings older than the retention period.

    Deletes DB rows and associated screenshot files. Use --days to override
    the ``AISPLOIT_EVIDENCE_RETENTION_DAYS`` setting for this run only.
    """
    settings = load_settings()
    retention = days if days > 0 else settings.evidence_retention_days
    store = EvidenceStore(settings.db_path)
    deleted = store.purge_old(retention)
    store.close()
    console.print(
        f"[bold green]Purged[/] {deleted} finding(s) older than {retention} day(s)."
    )


@app.command()
def login(
    target: str = typer.Argument(..., help="Target URL to authenticate against"),
    out: Path = typer.Option(
        Path("./auth/state.json"), "--out",
        help="Output path for the captured storage_state JSON",
    ),
    keyring_name: str = typer.Option(
        "", "--keyring",
        help="Store in OS keyring under this name instead of a file",
    ),
    headless: bool = typer.Option(
        False, "--headless",
        help="Run browser headless (default: visible for interactive login)",
    ),
) -> None:
    """D6: Interactively capture an authenticated session (Playwright).

    Opens a real browser pointed at the target. Log in, then the session
    state (cookies + localStorage) is saved to ``--out`` or the OS keyring.

    Interactive only — not for headless CI. In CI, inject auth via transport
    config or environment variables.
    """
    import asyncio

    console.print(f"[bold cyan]Starting interactive auth capture for[/] {target}")
    console.print(
        "[dim]A browser window will open. Log in, then this command will "
        "capture the session.[/dim]"
    )

    capture = AuthCapture(target, headless=headless)
    try:
        state = asyncio.run(capture.capture())
    except AuthCaptureError as exc:
        console.print(f"[bold red]AUTH CAPTURE ERROR:[/] {exc}")
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        console.print(f"[bold red]ERROR:[/] {exc}")
        raise typer.Exit(code=1) from exc

    kr = keyring_name or None
    location = save_auth_state(state, out_path=out, keyring_name=kr)
    console.print(f"[bold green]Auth state saved[/] → {location}")
    console.print(
        "[dim]Use this path (or keyring name) in your transport config "
        "under 'storage_state' or 'auth_headers'.[/dim]"
    )


@app.command()
def export(
    run_id: str = typer.Argument(..., help="Run ID to export from"),
    payload_id: str = typer.Argument(..., help="Payload ID of the finding to export"),
    fmt: str = typer.Option(
        "markdown", "--format",
        help="Output format: hackerone | huntr | markdown",
    ),
    out: Path | None = typer.Option(
        None, "--out",
        help="Write to file (default: stdout)",
    ),
) -> None:
    """D5b: Export a finding as a paste-ready bug-bounty submission."""
    from aisploit_recon.reporting.export import ExportFormat

    try:
        export_fmt = ExportFormat(fmt)
    except ValueError:
        console.print(
            f"[bold red]ERROR:[/] Invalid format {fmt!r}. "
            f"Use: hackerone, huntr, or markdown"
        )
        raise typer.Exit(code=1) from None

    settings = load_settings()
    store = EvidenceStore(settings.db_path)
    try:
        report = export_finding(store, run_id, payload_id, export_fmt)
    except KeyError as exc:
        console.print(f"[bold red]ERROR:[/] {exc}")
        raise typer.Exit(code=1) from exc
    finally:
        store.close()

    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report, encoding="utf-8")
        console.print(f"[bold green]Exported[/] {payload_id} → {out}")
    else:
        console.print(report)


@app.command()
def diff(
    run_a: str = typer.Argument(..., help="First run ID (baseline)"),
    run_b: str = typer.Argument(..., help="Second run ID (current)"),
) -> None:
    """D5b: Diff two runs — show new, resolved, and unchanged findings."""
    settings = load_settings()
    store = EvidenceStore(settings.db_path)
    result = diff_runs(store, run_a, run_b)
    store.close()

    console.print(f"[bold]Diff: {run_a} → {run_b}[/]\n")

    if result.new_findings:
        console.print(f"[bold red]NEW ({len(result.new_findings)})[/]")
        for f in result.new_findings:
            console.print(f"  + {f['payload_id']} ({f['verdict']}) — {f['target_url']}")
    if result.resolved_findings:
        console.print(f"\n[bold green]RESOLVED ({len(result.resolved_findings)})[/]")
        for f in result.resolved_findings:
            console.print(f"  - {f['payload_id']} ({f['verdict']}) — {f['target_url']}")
    if result.unchanged_findings:
        console.print(f"\n[dim]UNCHANGED ({len(result.unchanged_findings)})[/]")
        for f in result.unchanged_findings:
            console.print(f"  = {f['payload_id']} ({f['verdict']}) — {f['target_url']}")

    if not result.has_changes:
        console.print("[dim]No changes between runs.[/]")


if __name__ == "__main__":
    app()
