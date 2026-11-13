"""
QuantumPulse CBOM Comparer
Compares two CBOM manifests (e.g. baseline vs remediated) to track post-quantum
migration progress, quantified risk score reduction, and resolved vulnerabilities.
"""

from pathlib import Path
from typing import Dict, Any, Tuple
from core.models import ComparisonDelta
from core.parser import CBOMParser
from core.policy_engine import PolicyEngine
from core.risk_calculator import RiskCalculator


class CBOMComparer:
    def __init__(self):
        self.parser = CBOMParser()
        self.policy_engine = PolicyEngine()
        self.risk_calculator = RiskCalculator()

    def compare_files(self, baseline_path: str | Path, target_path: str | Path) -> ComparisonDelta:
        """Compares baseline CBOM with target CBOM and calculates migration delta."""
        b_path = Path(baseline_path)
        t_path = Path(target_path)

        _, b_raw_assets = self.parser.parse_file(b_path)
        b_assets = self.policy_engine.evaluate_assets(b_raw_assets)
        b_qri, _ = self.risk_calculator.calculate_qri(b_assets)

        _, t_raw_assets = self.parser.parse_file(t_path)
        t_assets = self.policy_engine.evaluate_assets(t_raw_assets)
        t_qri, _ = self.risk_calculator.calculate_qri(t_assets)

        # Map asset names & families
        b_names = set(f"{a.name}:{a.key_size or ''}" for a in b_assets)
        t_names = set(f"{a.name}:{a.key_size or ''}" for a in t_assets)

        resolved = list(b_names - t_names)
        introduced = list(t_names - b_names)

        qri_delta = round(t_qri.overall_score - b_qri.overall_score, 1)
        if b_qri.overall_score > 0:
            reduction_pct = round(((b_qri.overall_score - t_qri.overall_score) / b_qri.overall_score) * 100.0, 1)
        else:
            reduction_pct = 0.0

        summary = (
            f"Migration Comparison: Baseline QRI was {b_qri.overall_score} ({b_qri.risk_level}) -> "
            f"Target QRI is {t_qri.overall_score} ({t_qri.risk_level}). "
            f"Risk reduction of {reduction_pct}% with {len(resolved)} algorithms remediated."
        )

        return ComparisonDelta(
            baseline_file=b_path.name,
            target_file=t_path.name,
            baseline_qri=b_qri.overall_score,
            target_qri=t_qri.overall_score,
            qri_delta=qri_delta,
            risk_reduction_percent=reduction_pct,
            resolved_vulnerabilities=resolved,
            new_vulnerabilities=introduced,
            remediated_count=len(resolved),
            remaining_count=t_qri.broken_count + t_qri.classical_vulnerable_count,
            summary=summary,
        )

