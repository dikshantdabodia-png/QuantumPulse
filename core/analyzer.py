"""
QuantumPulse Core Unified Analyzer Orchestrator
Coordinates parsing, CycloneDX standard validation, policy evaluation,
QRI calculation, and NIST migration advisory generation.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from core.models import AnalysisReport
from core.parser import CBOMParser
from core.policy_engine import PolicyEngine
from core.risk_calculator import RiskCalculator
from core.nist_mapper import NISTMigrationAdvisor


class QuantumPulseAnalyzer:
    def __init__(
        self,
        schema_path: Optional[Path] = None,
        rules_path: Optional[Path] = None,
        catalog_path: Optional[Path] = None,
        oids_path: Optional[Path] = None,
    ):
        self.parser = CBOMParser(schema_path=schema_path, oids_path=oids_path)
        self.policy_engine = PolicyEngine(rules_path=rules_path)
        self.risk_calculator = RiskCalculator()
        self.nist_advisor = NISTMigrationAdvisor(catalog_path=catalog_path)

    def analyze_file(self, file_path: str | Path) -> AnalysisReport:
        """Runs the complete 4-stage pipeline on a given CBOM manifest file."""
        path = Path(file_path)
        timestamp = datetime.now(timezone.utc).isoformat()

        # Stage 1: Ingestion, Validation & Normalization
        compliance_report, raw_assets = self.parser.parse_file(path)

        # Stage 2: Cryptographic Policy & Heuristics Evaluation
        evaluated_assets = self.policy_engine.evaluate_assets(raw_assets)

        # Stage 3: Quantum Risk Index & Exposure Calculation
        qri_summary, scored_assets = self.risk_calculator.calculate_qri(evaluated_assets)

        # Stage 4: NIST PQC Remediation & Advisory Mapping
        directives = self.nist_advisor.generate_advisories(scored_assets)

        return AnalysisReport(
            timestamp=timestamp,
            manifest_name=path.name,
            standard_compliance=compliance_report,
            qri_summary=qri_summary,
            assets=scored_assets,
            directives=directives,
        )

