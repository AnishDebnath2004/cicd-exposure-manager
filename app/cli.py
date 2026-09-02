"""
app/cli.py
DevSecOps CI/CD Exposure Manager - Universal Security Quality Gate CLI.
Supports scanning local directories, remote Git URLs, SARIF export, and viewing history.
"""

import sys
import json
import click
# pyrefly: ignore [missing-import]
from rich.console import Console
# pyrefly: ignore [missing-import]
from rich.table import Table
# pyrefly: ignore [missing-import]
from rich.panel import Panel
from app.config import settings
from app.models.schemas import ScanRequest, SeverityLevel
from app.core.orchestrator import ExposureOrchestrator
from app.core.storage import storage

console = Console(legacy_windows=False)


@click.command()
@click.option("--path", "-p", default=None, help="Path to local target repository to audit.")
@click.option("--url", "-u", default=None, help="Remote Git repository URL to clone and audit (e.g., https://github.com/org/repo).")
@click.option("--branch", "-b", default=None, help="Specific Git branch or tag to clone and audit.")
@click.option(
    "--fail-on", "-f",
    default=settings.policy_gate.DEFAULT_FAIL_SEVERITY,
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    help="Threshold severity to fail CI/CD build."
)
@click.option(
    "--max-pes", "-m",
    default=settings.policy_gate.DEFAULT_MAX_PES,
    type=float,
    help="Maximum allowable Pipeline Exposure Score (PES)."
)
@click.option("--sarif", type=str, default=None, help="File path to export SARIF 2.1.0 report.")
@click.option("--json-out", type=str, default=None, help="File path to export raw JSON report.")
@click.option("--history", is_flag=True, help="Display recent scan history timeline.")
def main(path: str, url: str, branch: str, fail_on: str, max_pes: float, sarif: str, json_out: str, history: bool):
    """DevSecOps CI/CD Exposure Manager - Security Quality Gate CLI."""
    console.print(Panel.fit(f"[bold blue]{settings.PROJECT_NAME}[/bold blue] | Universal Security Auditor", border_style="blue"))

    if history:
        scans = storage.list_scans(limit=15)
        if not scans:
            console.print("[yellow]No previous scan history found.[/yellow]")
            return

        hist_table = Table(title="Recent Scan History Timeline")
        hist_table.add_column("Scan ID", justify="center")
        hist_table.add_column("Repository")
        hist_table.add_column("Source")
        hist_table.add_column("Date")
        hist_table.add_column("PES Score", justify="right")
        hist_table.add_column("Grade", justify="center")
        hist_table.add_column("Gate Result", justify="center")

        for s in scans:
            gate_col = "[green]PASS[/green]" if s.policy_passed else "[red]FAIL[/red]"
            hist_table.add_row(
                s.scan_id[:8],
                s.repo_name,
                s.source_type,
                s.timestamp.strftime("%Y-%m-%d %H:%M"),
                f"{s.pipeline_exposure_score:.1f}",
                s.risk_grade,
                gate_col
            )
        console.print(hist_table)
        return

    target_path = path
    if not url and not target_path:
        target_path = "."

    orchestrator = ExposureOrchestrator()
    request = ScanRequest(
        target_path=target_path,
        repo_url=url,
        branch=branch,
        fail_on_severity=SeverityLevel(fail_on),
        max_allowed_pes=max_pes
    )

    console.print(f"[dim]Initiating audit on: {url or target_path} ...[/dim]")

    try:
        result = orchestrator.run_scan(request)
    except Exception as e:
        console.print(f"[bold red]Scan Failed:[/bold red] {e}")
        sys.exit(1)

    s = result.summary
    table = Table(title=f"Security Exposure Findings: {result.repo_name}")
    table.add_column("Severity", justify="center")
    table.add_column("Category")
    table.add_column("Finding Title")
    table.add_column("Location")

    for f in result.findings:
        sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        color = "red" if sev_val in ["CRITICAL", "HIGH"] else "yellow"
        table.add_row(
            f"[{color}]{sev_val}[/{color}]",
            f.category.value if hasattr(f.category, "value") else str(f.category),
            f.title,
            f"{f.file_path}:{f.line_number or 1}"
        )

    console.print(table)

    # Output Metric Box
    status_text = "[bold green]PASSED[/bold green]" if s.policy_passed else "[bold red]FAILED (BUILD BLOCKED)[/bold red]"
    console.print(f"\n[bold]Pipeline Exposure Score (PES):[/bold] {s.pipeline_exposure_score}/100 ([bold]{s.risk_grade}[/bold])")
    console.print(f"[bold]Quality Gate Policy Result:[/bold] {status_text}")
    console.print(f"[dim]Scanned {s.scanned_files_count} files in {s.scan_duration_seconds}s (Scan ID: {result.scan_id})[/dim]\n")

    # Exports if requested
    if sarif:
        sarif_data = storage.export_sarif(result)
        with open(sarif, "w", encoding="utf-8") as sf:
            json.dump(sarif_data, sf, indent=2)
        console.print(f"[green][OK] SARIF 2.1.0 exported to: {sarif}[/green]")

    if json_out:
        with open(json_out, "w", encoding="utf-8") as jf:
            jf.write(result.model_dump_json(indent=2))
        console.print(f"[green][OK] Raw JSON report exported to: {json_out}[/green]")

    if not s.policy_passed:
        console.print("[bold red][!] Build failed due to security policy violations![/bold red]")
        sys.exit(1)
    else:
        console.print("[bold green][OK] Pipeline security gate passed![/bold green]")
        sys.exit(0)


if __name__ == "__main__":
    main()