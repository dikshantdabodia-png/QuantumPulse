"""
QuantumPulse Empirical Performance Benchmark Suite (v1.0.0)
Measures ingestion, schema validation, policy evaluation, and QRI calculation throughput
across small, medium, and massive enterprise datasets (10 to 5,000+ cryptographic assets).
"""

import sys
import time
import tracemalloc
from pathlib import Path
import pandas as pd
from rich.console import Console
from rich.table import Table
from rich import box

# Ensure project root in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.analyzer import QuantumPulseAnalyzer
from benchmarks.generate_synthetic import generate_synthetic_cbom

console = Console()


def run_benchmarks(asset_counts=[10, 100, 500, 1000, 2500, 5000]):
    analyzer = QuantumPulseAnalyzer()
    results = []

    console.print()
    console.print("[bold cyan]Starting QuantumPulse Empirical Performance Benchmark Suite...[/bold cyan]")
    console.print()

    for count in asset_counts:
        # Generate synthetic manifest in memory
        manifest_data = generate_synthetic_cbom(num_assets=count, app_name=f"Enterprise-Scale-App-{count}")

        tracemalloc.start()
        start_time = time.perf_counter()

        # Ingestion & Validation
        compliance, raw_assets = analyzer.parser.parse_data(manifest_data, manifest_name=f"synthetic_{count}.json")
        # Policy Evaluation
        evaluated = analyzer.policy_engine.evaluate_assets(raw_assets)
        # QRI Risk Calculation
        qri_summary, scored = analyzer.risk_calculator.calculate_qri(evaluated)
        # NIST Advisory
        directives = analyzer.nist_advisor.generate_advisories(scored)

        duration = time.perf_counter() - start_time
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        throughput = round(count / max(0.0001, duration), 1)
        peak_mb = round(peak_mem / (1024 * 1024), 2)

        results.append({
            "Asset Count": count,
            "Execution Time (s)": round(duration, 4),
            "Throughput (assets/sec)": throughput,
            "Peak Memory (MB)": peak_mb,
            "QRI Score": qri_summary.overall_score,
            "Directives Count": len(directives),
        })

    # Render Table
    table = Table(title="QuantumPulse Execution Performance Benchmarks", box=box.ROUNDED, header_style="bold green")
    table.add_column("Cryptographic Assets", justify="right", style="bold")
    table.add_column("Total Latency (s)", justify="right")
    table.add_column("Throughput (assets/sec)", justify="right", style="cyan")
    table.add_column("Peak RAM (MB)", justify="right")
    table.add_column("QRI Score", justify="right")
    table.add_column("Directives Generated", justify="right")

    for r in results:
        table.add_row(
            f"{r['Asset Count']:,}",
            f"{r['Execution Time (s)']:.4f}s",
            f"{r['Throughput (assets/sec)']:,} /s",
            f"{r['Peak Memory (MB)']:.2f} MB",
            f"{r['QRI Score']:.1f}",
            str(r["Directives Count"]),
        )

    console.print(table)
    console.print()
    return results


if __name__ == "__main__":
    run_benchmarks()

