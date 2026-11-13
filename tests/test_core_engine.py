"""
Comprehensive unit tests covering Policy Engine, Risk Calculator, NIST Mapper,
CBOM Comparer, and Multi-Format Reporter.
"""

from pathlib import Path
import pytest
from core import (
    QuantumPulseAnalyzer,
    PolicyEngine,
    RiskCalculator,
    NISTMigrationAdvisor,
    CBOMComparer,
    Reporter,
    ComplianceStatus,
    AlgorithmFamily,
)


@pytest.fixture
def analyzer():
    return QuantumPulseAnalyzer()


def test_enterprise_banking_analysis(analyzer):
    path = Path("samples/enterprise_banking_cbom.json")
    report = analyzer.analyze_file(path)
    
    assert report.manifest_name == "enterprise_banking_cbom.json"
    assert report.standard_compliance.is_valid is True
    assert report.qri_summary.total_crypto_assets == 6
    assert report.qri_summary.broken_count >= 2  # RSA-1024, 3DES, SHA-1, etc.
    assert report.qri_summary.risk_level in ["HIGH", "CRITICAL"]
    assert report.qri_summary.overall_score >= 65.0
    assert len(report.directives) >= 4


def test_cloud_pqc_analysis(analyzer):
    path = Path("samples/cloud_microservice_pqc_cbom.json")
    report = analyzer.analyze_file(path)
    
    assert report.qri_summary.risk_level == "SAFE"
    assert report.qri_summary.overall_score <= 15.0
    assert report.qri_summary.broken_count == 0
    assert report.qri_summary.classical_vulnerable_count == 0
    assert report.qri_summary.safe_count == 4
    assert len(report.directives) == 0


def test_contextual_heuristic_md5_downgrade(analyzer):
    # Banking CBOM has MD5 with context "file-checksum"
    path = Path("samples/enterprise_banking_cbom.json")
    report = analyzer.analyze_file(path)
    md5_asset = next(a for a in report.assets if a.name == "MD5")
    assert "file-checksum" in md5_asset.context_purpose
    assert md5_asset.individual_qri <= 25.0  # severely reduced exposure due to non-security context


def test_contextual_heuristic_md5_escalation(analyzer):
    # Shadow IT CBOM has MD5 with context "password-hash"
    path = Path("samples/shadow_it_sprawl_cbom.json")
    report = analyzer.analyze_file(path)
    md5_asset = next(a for a in report.assets if a.name == "MD5")
    assert md5_asset.compliance_status == ComplianceStatus.BROKEN_INSECURE
    assert md5_asset.individual_qri >= 80.0  # critical violation


def test_nist_mapper_directions(analyzer):
    path = Path("samples/enterprise_banking_cbom.json")
    report = analyzer.analyze_file(path)
    
    rsa_directive = next((d for d in report.directives if "RSA" in d.current_algorithm), None)
    assert rsa_directive is not None
    assert "ML-KEM" in rsa_directive.recommended_replacement or "ML-DSA" in rsa_directive.recommended_replacement

    des_directive = next((d for d in report.directives if "3DES" in d.current_algorithm), None)
    assert des_directive is not None
    assert des_directive.recommended_replacement == "AES-256-GCM"


def test_cbom_comparer():
    comparer = CBOMComparer()
    delta = comparer.compare_files(
        baseline_path="samples/enterprise_banking_cbom.json",
        target_path="samples/cloud_microservice_pqc_cbom.json",
    )
    assert delta.baseline_qri > delta.target_qri
    assert delta.risk_reduction_percent > 70.0
    assert delta.remediated_count > 0


def test_reporter_outputs(analyzer, tmp_path):
    path = Path("samples/enterprise_banking_cbom.json")
    report = analyzer.analyze_file(path)

    # JSON export
    json_out = Reporter.to_json(report)
    assert "QuantumPulse" in json_out or "QRI" in json_out

    # SARIF export
    sarif_dict = Reporter.to_sarif(report)
    assert sarif_dict["version"] == "2.1.0"
    assert len(sarif_dict["runs"][0]["results"]) > 0

    # Markdown export
    md_out = Reporter.to_markdown(report)
    assert "# QuantumPulse Security & PQC Migration Advisory" in md_out

    # PDF export
    pdf_file = tmp_path / "test_report.pdf"
    Reporter.to_pdf(report, pdf_file)
    assert pdf_file.exists()
    assert pdf_file.stat().st_size > 1000

