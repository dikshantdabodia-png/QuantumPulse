#!/usr/bin/env python3
"""
QuantumPulse Interactive Quickstart & Demonstration Script
Executes an end-to-end automated walkthrough of QuantumPulse's core capabilities:
1. Scanning an Enterprise Legacy CBOM
2. Evaluating NIST PQC Migration Directives
3. Comparing CBOM Deltas (Migration Progress)
4. Generating a CBOM from Local Source Code
5. Generating Automated Code Migration Patches
6. Running Real-Time Performance Benchmarks
"""

import sys
import time
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich import box

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.analyzer import QuantumPulseAnalyzer
from core.cbom_comparer import CBOMComparer
from core.generator import CodebaseCBOMGenerator
from core.patcher import CodePatcher
from benchmarks.run_benchmark import run_benchmarks

console = Console()


def print_step(title: str, description: str):
    console.print()
    console.print(Panel(f"[bold white]{description}[/bold white]", title=f"[bold cyan]{title}[/bold cyan]", border_style="cyan", box=box.ROUNDED))
    time.sleep(1)


def main():
    console.clear()
    console.print(Panel.fit(
        "[bold white on blue] QuantumPulse: CBOM Analyzer & PQC Migration Advisor [/bold white on blue]\n"
        "[dim]Interactive Demonstration & Automated Validation Walkthrough[/dim]",
        box=box.DOUBLE,
    ))

    # --- Step 1: Scan Enterprise Banking CBOM ---
    print_step(
        "Step 1: Auditing Enterprise Legacy CBOM",
        "Ingesting 'samples/enterprise_banking_cbom.json' (Simulates classical financial infrastructure with RSA-1024, 3DES, and MD5)..."
    )
    analyzer = QuantumPulseAnalyzer()
    report = analyzer.analyze_file(PROJECT_ROOT / "samples" / "enterprise_banking_cbom.json")
    
    qri = report.qri_summary
    console.print(f"• [bold]Discovered Cryptographic Assets:[/bold] {qri.total_crypto_assets}")
    console.print(f"• [bold]Calculated Quantum Risk Index (QRI):[/bold] [bold red]{qri.overall_score} / 100 ({qri.risk_level})[/bold red]")
    console.print(f"• [bold]Shor-Vulnerable Public Keys:[/bold] {qri.classical_vulnerable_count}")
    console.print(f"• [bold]Classically Broken Primitives:[/bold] {qri.broken_count}")
    console.print(f"• [bold]Harvest-Now-Decrypt-Later Threat Index:[/bold] {qri.hndl_exposure_index} / 100")
    console.print(f"• [bold]CycloneDX 1.6 Standard Adherence:[/bold] [bold green]{report.standard_compliance.adherence_score}%[/bold green]")

    # --- Step 2: NIST PQC Migration Directives ---
    print_step(
        "Step 2: Automated NIST PQC Migration Advisories",
        f"Mapping {len(report.directives)} identified vulnerabilities directly to NIST FIPS 203/204/205 standards..."
    )
    for d in report.directives[:3]:
        console.print(f"  ➔ [bold yellow]{d.asset_id}[/bold yellow] ({d.current_algorithm}) ➔ [bold green]{d.recommended_replacement}[/bold green] [{d.nist_standard}] - [red]{d.priority_tier}[/red]")

    # --- Step 3: Migration Delta Comparison ---
    print_step(
        "Step 3: Cryptographic Migration Delta Tracking",
        "Comparing Baseline Legacy Banking CBOM against Remediated Cloud Microservice CBOM..."
    )
    comparer = CBOMComparer()
    delta = comparer.compare_files(
        PROJECT_ROOT / "samples" / "enterprise_banking_cbom.json",
        PROJECT_ROOT / "samples" / "cloud_microservice_pqc_cbom.json",
    )
    console.print(f"• [bold]Baseline QRI:[/bold] {delta.baseline_qri} ➔ [bold]Target QRI:[/bold] {delta.target_qri}")
    console.print(f"• [bold]Net Cryptographic Risk Reduction:[/bold] [bold green]{delta.risk_reduction_percent}%[/bold green]")
    console.print(f"• [bold]Remediated Legacy Algorithms:[/bold] {len(delta.resolved_vulnerabilities)}")

    # --- Step 4: Codebase-to-CBOM Scanner ---
    print_step(
        "Step 4: Direct Codebase-to-CBOM Scanner",
        "Scanning local 'core/' directory to extract cryptographic implementations without needing an upstream CBOM..."
    )
    generator = CodebaseCBOMGenerator()
    cbom = generator.scan_directory(PROJECT_ROOT / "core", app_name="QuantumPulse-Internal")
    console.print(f"• [bold]Extracted Components:[/bold] {len(cbom['components'])}")
    console.print(f"• [bold]Synthesized Format:[/bold] {cbom['bomFormat']} {cbom['specVersion']} (ECMA-424 Compliant)")

    # --- Step 5: Automated Code Patcher ---
    print_step(
        "Step 5: Automated Code Migration Patcher",
        "Generating drop-in Python hybrid key exchange wrapper (X25519 + NIST FIPS 203 ML-KEM-768)..."
    )
    patch = CodePatcher.get_patch_snippet("RSA-2048", "ML-KEM-768", language="python")
    console.print(f"[dim]{patch['explanation']}[/dim]")
    console.print("[green]Ready-to-use drop-in code snippet generated successfully.[/green]")

    # --- Step 6: Empirical Benchmark ---
    print_step(
        "Step 6: Empirical Execution Stress Benchmarks",
        "Running high-throughput scaling benchmarks across 10, 100, and 500 synthetic cryptographic assets..."
    )
    run_benchmarks(asset_counts=[10, 100, 500])

    console.print()
    console.print(Panel(
        "[bold green]✔ Demonstration Complete![/bold green]\n\n"
        "To launch the interactive Web GUI Dashboard, run:\n"
        "[bold cyan]streamlit run gui/dashboard.py[/bold cyan]\n\n"
        "To run full CLI scans, run:\n"
        "[bold cyan]python cli/main.py scan samples/enterprise_banking_cbom.json[/bold cyan]",
        title="[bold green]QuantumPulse Status: Production Ready[/bold green]",
        border_style="green",
        box=box.ROUNDED,
    ))


if __name__ == "__main__":
    main()

