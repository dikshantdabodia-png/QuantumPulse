#!/usr/bin/env python3
"""
QuantumPulse Terminal Command Line Interface (v1.0.0)
Powered by Typer and Rich. Supports interactive terminal scanning,
CI/CD governance gate thresholds, multi-format exports (PDF, SARIF, JSON, Markdown),
and CBOM delta comparisons.
"""

import sys
from pathlib import Path

# Ensure QuantumPulse project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from core.analyzer import QuantumPulseAnalyzer
from core.cbom_comparer import CBOMComparer
from core.reporter import Reporter
from core.generator import CodebaseCBOMGenerator
from core.patcher import CodePatcher
from core.models import ComplianceStatus

app = typer.Typer(
    name="quantumpulse",
    help="QuantumPulse: CBOM File Analyzer & NIST Post-Quantum Cryptography Migration Advisor",
    add_completion=False,
)
console = Console()


def _get_risk_style(risk_level: str) -> str:
    return {
        "SAFE": "bold green",
        "LOW": "bold cyan",
        "MEDIUM": "bold yellow",
        "HIGH": "bold color(208)",
        "CRITICAL": "bold red",
    }.get(risk_level, "white")


@app.command(name="scan")
def scan_cbom(
    cbom_file: Path = typer.Argument(..., help="Path to CycloneDX 1.6 CBOM JSON manifest."),
    output_format: str = typer.Option("terminal", "--format", "-f", help="Output format: terminal, json, sarif, markdown, pdf"),
    output_path: Optional[Path] = typer.Option(None, "--output", "-o", help="File destination for exported report."),
    fail_on_broken: bool = typer.Option(False, "--fail-on-broken", help="Exit with code 1 if classically broken primitives exist (CI/CD gate)."),
    fail_on_shor: bool = typer.Option(False, "--fail-on-shor", help="Exit with code 2 if Shor-vulnerable primitives exist."),
    max_qri: Optional[float] = typer.Option(None, "--max-qri", help="Fail CI/CD build if overall QRI exceeds this threshold (0-100)."),
):
    """Scan and audit a CycloneDX CBOM file for quantum risks and NIST PQC migration directives."""
    if not cbom_file.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {cbom_file}")
        raise typer.Exit(code=1)

    with console.status("[bold cyan]Analyzing Cryptographic Bill of Materials...", spinner="dots"):
        analyzer = QuantumPulseAnalyzer()
        report = analyzer.analyze_file(cbom_file)

    qri = report.qri_summary
    comp = report.standard_compliance

    # Handle structured non-terminal exports
    fmt = output_format.lower()
    if fmt == "json":
        json_str = Reporter.to_json(report)
        if output_path:
            output_path.write_text(json_str, encoding="utf-8")
            console.print(f"[green]Saved JSON report to: {output_path}[/green]")
        else:
            console.print(json_str)
        _handle_exit_gates(qri, fail_on_broken, fail_on_shor, max_qri)
        return

    if fmt == "sarif":
        sarif_data = Reporter.to_sarif(report)
        import json
        sarif_str = json.dumps(sarif_data, indent=2)
        if output_path:
            output_path.write_text(sarif_str, encoding="utf-8")
            console.print(f"[green]Saved SARIF v2.1.0 report to: {output_path}[/green]")
        else:
            console.print(sarif_str)
        _handle_exit_gates(qri, fail_on_broken, fail_on_shor, max_qri)
        return

    if fmt == "markdown":
        md_str = Reporter.to_markdown(report)
        if output_path:
            output_path.write_text(md_str, encoding="utf-8")
            console.print(f"[green]Saved Markdown summary to: {output_path}[/green]")
        else:
            console.print(md_str)
        _handle_exit_gates(qri, fail_on_broken, fail_on_shor, max_qri)
        return

    if fmt == "pdf":
        target_pdf = output_path or Path(f"{cbom_file.stem}_quantumpulse_audit.pdf")
        Reporter.to_pdf(report, target_pdf)
        console.print(f"[bold green]Executive PDF audit report generated at: {target_pdf}[/bold green]")
        _handle_exit_gates(qri, fail_on_broken, fail_on_shor, max_qri)
        return

    # Terminal Rich Visual Output
    _render_terminal_report(report)
    _handle_exit_gates(qri, fail_on_broken, fail_on_shor, max_qri)


def _render_terminal_report(report):
    qri = report.qri_summary
    comp = report.standard_compliance

    # Banner Header
    console.print()
    banner = Text(" QuantumPulse: CBOM Analyzer & PQC Migration Advisor ", style="bold white on blue")
    console.print(banner, justify="center")
    console.print(f"[dim]Manifest: {report.manifest_name} | Timestamp: {report.timestamp}[/dim]", justify="center")
    console.print()

    # Executive Overview Cards
    risk_style = _get_risk_style(qri.risk_level)
    overview_text = (
        f"[bold]Quantum Risk Index (QRI):[/bold] [{risk_style}]{qri.overall_score} / 100 ({qri.risk_level})[/{risk_style}]\n"
        f"[bold]Total Cryptographic Assets:[/bold] {qri.total_crypto_assets} | "
        f"[bold green]Quantum-Safe:[/bold green] {qri.safe_count} | "
        f"[bold yellow]Shor-Vulnerable:[/bold yellow] {qri.classical_vulnerable_count} | "
        f"[bold red]Broken/Deprecated:[/bold red] {qri.broken_count} | "
        f"[bold cyan]Hybrid Active:[/bold cyan] {qri.hybrid_count}\n"
        f"[bold]CycloneDX Standard Adherence:[/bold] [bold green]{comp.adherence_score}%[/bold green] (Spec {comp.spec_version}) | "
        f"[bold]Analysis Confidence:[/bold] {qri.confidence_score}% | "
        f"[bold]HNDL Threat Index:[/bold] {qri.hndl_exposure_index}/100"
    )
    console.print(Panel(overview_text, title="Executive Post-Quantum Posture", border_style="blue", box=box.ROUNDED))
    console.print()

    # Asset Inventory Table
    asset_table = Table(title="Discovered Cryptographic Asset Inventory", box=box.SIMPLE_HEAVY, header_style="bold magenta")
    asset_table.add_column("ID", style="dim", width=8)
    asset_table.add_column("Algorithm", style="bold")
    asset_table.add_column("Family")
    asset_table.add_column("Key Size", justify="right")
    asset_table.add_column("Context / Purpose")
    asset_table.add_column("Status")
    asset_table.add_column("Asset QRI", justify="right")

    for a in report.assets:
        status_style = {
            ComplianceStatus.COMPLIANT_QUANTUM_SAFE: "green",
            ComplianceStatus.HYBRID_TRANSITION: "cyan",
            ComplianceStatus.LEGACY_CLASSICAL_VULNERABLE: "yellow",
            ComplianceStatus.BROKEN_INSECURE: "bold red",
        }.get(a.compliance_status, "white")

        asset_table.add_row(
            a.id,
            a.name,
            a.family.value,
            str(a.key_size or "-"),
            a.context_purpose or "[dim]unspecified[/dim]",
            f"[{status_style}]{a.compliance_status.value.replace('_', ' ')}[/{status_style}]",
            f"[{status_style}]{a.individual_qri}[/{status_style}]",
        )
    console.print(asset_table)
    console.print()

    # Migration Directives Table
    if report.directives:
        dir_table = Table(title="NIST Post-Quantum Cryptography Migration Directives", box=box.ROUNDED, header_style="bold green")
        dir_table.add_column("Asset", style="dim")
        dir_table.add_column("Current Algorithm")
        dir_table.add_column("NIST Replacement", style="bold green")
        dir_table.add_column("Standard")
        dir_table.add_column("Priority Tier", style="bold")
        dir_table.add_column("Deadline", style="bold yellow")
        dir_table.add_column("Trade-off / Overhead")

        for d in report.directives:
            tier_style = "bold red" if "Tier 1" in d.priority_tier else "bold yellow"
            dir_table.add_row(
                d.asset_id,
                d.current_algorithm,
                d.recommended_replacement,
                d.nist_standard,
                f"[{tier_style}]{d.priority_tier}[/{tier_style}]",
                d.deprecation_deadline,
                d.public_key_overhead or d.ciphertext_overhead or "Low",
            )
        console.print(dir_table)
        console.print()

    # Audit Gaps Panel
    if qri.audit_gaps_count > 0:
        gaps_text = "\n".join([
            f"• [bold yellow]{a.name}[/bold yellow] ({a.id}): {g.description}"
            for a in report.assets for g in a.audit_gaps
        ][:5])
        if qri.audit_gaps_count > 5:
            gaps_text += f"\n[dim]... and {qri.audit_gaps_count - 5} more audit gaps.[/dim]"
        console.print(Panel(gaps_text, title=f"Audit Gaps Detected ({qri.audit_gaps_count})", border_style="yellow", box=box.ROUNDED))
        console.print()


def _handle_exit_gates(qri, fail_on_broken: bool, fail_on_shor: bool, max_qri: Optional[float]):
    if fail_on_broken and qri.broken_count > 0:
        console.print(f"[bold red]CI/CD Gate Failed: Found {qri.broken_count} classically broken primitives.[/bold red]")
        sys.exit(1)
    if fail_on_shor and qri.classical_vulnerable_count > 0:
        console.print(f"[bold red]CI/CD Gate Failed: Found {qri.classical_vulnerable_count} Shor-vulnerable primitives.[/bold red]")
        sys.exit(2)
    if max_qri is not None and qri.overall_score > max_qri:
        console.print(f"[bold red]CI/CD Gate Failed: Overall QRI {qri.overall_score} exceeds max threshold of {max_qri}.[/bold red]")
        sys.exit(3)


@app.command(name="generate")
def generate_cbom(
    source_target: str = typer.Argument(..., help="Path to local project directory OR public GitHub repository URL."),
    output_cbom: Path = typer.Option(Path("generated_cbom.json"), "--output", "-o", help="Target CBOM JSON manifest file."),
    auto_scan: bool = typer.Option(True, "--scan/--no-scan", help="Automatically run PQC security scan after generating manifest."),
):
    """Scan local source code or a public GitHub repository to generate a CycloneDX 1.6 CBOM."""
    generator = CodebaseCBOMGenerator()
    is_github = generator.is_github_url(source_target)

    if not is_github and not Path(source_target).exists():
        console.print(f"[bold red]Error: Local source directory '{source_target}' does not exist.[/bold red]")
        raise typer.Exit(code=1)

    spin_msg = f"Cloning & scanning GitHub repository '{source_target}'..." if is_github else f"Scanning '{source_target}' for cryptographic implementations..."
    with console.status(f"[bold cyan]{spin_msg}[/bold cyan]", spinner="dots"):
        import json
        cbom_data = generator.scan_target(source_target)
        output_cbom.write_text(json.dumps(cbom_data, indent=2), encoding="utf-8")

    console.print(f"[bold green]Successfully generated CycloneDX 1.6 CBOM with {len(cbom_data.get('components', []))} components at: {output_cbom}[/bold green]")
    
    if auto_scan:
        console.print()
        scan_cbom(
            cbom_file=output_cbom,
            output_format="terminal",
            output_path=None,
            fail_on_broken=False,
            fail_on_shor=False,
            max_qri=None,
        )


@app.command(name="compare")
def compare_cboms(
    baseline_file: Path = typer.Argument(..., help="Path to initial/baseline CBOM JSON manifest."),
    target_file: Path = typer.Argument(..., help="Path to upgraded/target CBOM JSON manifest."),
):
    """Compare two CBOM manifests to quantify migration progress and risk reduction."""
    if not baseline_file.exists() or not target_file.exists():
        console.print("[bold red]Error: Both CBOM manifest files must exist.[/bold red]")
        raise typer.Exit(code=1)

    with console.status("[bold cyan]Comparing CBOM manifests...", spinner="dots"):
        comparer = CBOMComparer()
        delta = comparer.compare_files(baseline_file, target_file)

    console.print()
    console.print(Panel(delta.summary, title="Post-Quantum Migration Comparison", border_style="green", box=box.ROUNDED))
    console.print()

    table = Table(title="Migration Metrics Delta", box=box.SIMPLE_HEAVY)
    table.add_column("Metric", style="bold")
    table.add_column("Baseline Manifest", style="yellow")
    table.add_column("Target Manifest", style="green")
    table.add_column("Delta / Impact", style="bold cyan")

    table.add_row("Manifest File", delta.baseline_file, delta.target_file, "-")
    table.add_row("Quantum Risk Index (QRI)", str(delta.baseline_qri), str(delta.target_qri), f"{delta.qri_delta:+0.1f}")
    table.add_row("Risk Reduction %", "0.0%", f"{delta.risk_reduction_percent}%", f"-{delta.risk_reduction_percent}%")
    table.add_row("Remediated Primitives", "0", str(delta.remediated_count), f"{delta.remediated_count} resolved")
    table.add_row("Remaining Vulnerable", "-", str(delta.remaining_count), "-")

    console.print(table)
    console.print()


@app.command(name="benchmark")
def run_benchmark_cmd(
    counts: str = typer.Option("10,100,500,1000,2500", "--counts", "-c", help="Comma-separated list of asset counts to benchmark."),
):
    """Run empirical stress benchmarks across small to enterprise CBOM sizes."""
    from benchmarks.run_benchmark import run_benchmarks
    try:
        asset_counts = [int(x.strip()) for x in counts.split(",") if x.strip()]
    except ValueError:
        console.print("[bold red]Error: Invalid comma-separated asset counts.[/bold red]")
        raise typer.Exit(code=1)

    run_benchmarks(asset_counts=asset_counts)


@app.command(name="patch")
def show_patch(
    algorithm: str = typer.Argument(..., help="Legacy algorithm to remediate (e.g. RSA, ECDH, ECDSA, AES-128)."),
    target_pqc: str = typer.Option("ML-KEM-768", "--target", "-t", help="NIST Post-Quantum target standard (ML-KEM-768, ML-DSA-65, etc.)."),
    language: str = typer.Option("python", "--lang", "-l", help="Target language/environment (python, openssl, nginx)."),
):
    """Generate copy-pasteable post-quantum code patch snippets and migration wrappers."""
    patch = CodePatcher.get_patch_snippet(algorithm, target_pqc, language=language)
    
    console.print()
    console.print(Panel(
        f"[bold]Legacy Algorithm:[/bold] {algorithm} ➔ [bold green]NIST Target:[/bold green] {target_pqc}\n"
        f"[bold]Target Environment:[/bold] {patch['language']}\n\n"
        f"[dim]{patch['explanation']}[/dim]",
        title="QuantumPulse Automated Migration Code Patcher",
        border_style="green",
        box=box.ROUNDED,
    ))
    console.print()
    from rich.syntax import Syntax
    lex = "python" if patch["language"].lower() == "python" else "nginx"
    syntax = Syntax(patch["code"], lex, theme="monokai", line_numbers=True)
    console.print(syntax)
    console.print()


@app.command(name="rules")
def show_rules():
    """List active compliance policies, cryptographic baselines, and NIST standards."""
    analyzer = QuantumPulseAnalyzer()
    rules = analyzer.policy_engine.algorithms_rules

    table = Table(title="QuantumPulse Cryptographic Policy Registry", box=box.ROUNDED, header_style="bold blue")
    table.add_column("Rule ID", style="dim")
    table.add_column("Algorithm", style="bold")
    table.add_column("Default Classification")
    table.add_column("Shor Impact")
    table.add_column("Grover Impact")
    table.add_column("Deprecation Deadline")

    for r in rules[:15]:
        shor = "[red]Yes[/red]" if r.get("shor_susceptible") else "[green]No[/green]"
        grover = "[yellow]Yes[/yellow]" if r.get("grover_susceptible") else "[green]No[/green]"
        table.add_row(
            r.get("id", "-"),
            r.get("name", "-"),
            r.get("classification", "CONDITIONAL"),
            shor,
            grover,
            r.get("deprecation_deadline", "2030"),
        )

    console.print(table)
    console.print()


if __name__ == "__main__":
    app()
