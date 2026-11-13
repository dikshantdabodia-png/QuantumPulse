"""
QuantumPulse Core Data Models
Strict Pydantic schemas representing cryptographic assets, CycloneDX compliance,
risk indexes, and migration directives.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ComplianceStatus(str, Enum):
    COMPLIANT_QUANTUM_SAFE = "COMPLIANT_QUANTUM_SAFE"
    LEGACY_CLASSICAL_VULNERABLE = "LEGACY_CLASSICAL_VULNERABLE"
    BROKEN_INSECURE = "BROKEN_INSECURE"
    HYBRID_TRANSITION = "HYBRID_TRANSITION"


class AlgorithmFamily(str, Enum):
    ASYMMETRIC_ENCRYPTION = "asymmetric-encryption"
    DIGITAL_SIGNATURE = "digital-signature"
    KEY_EXCHANGE = "key-exchange"
    SYMMETRIC_CIPHER = "symmetric-cipher"
    HASH_DIGEST = "hash-digest"
    PQC_KEM = "pqc-kem"
    PQC_SIGNATURE = "pqc-signature"
    HYBRID = "hybrid"
    UNKNOWN = "unknown"


class AuditGap(BaseModel):
    field_name: str
    description: str
    impact: str = "Medium"


class CryptographicAsset(BaseModel):
    id: str
    name: str = "UNKNOWN"
    raw_name: str = "UNKNOWN"
    oid: Optional[str] = None
    family: AlgorithmFamily = AlgorithmFamily.UNKNOWN
    primitive: Optional[str] = None
    key_size: Optional[int] = None
    curve: Optional[str] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    component_name: str = "Unknown Component"
    component_type: str = "cryptographic-asset"
    bom_ref: Optional[str] = None
    context_purpose: Optional[str] = None
    
    compliance_status: ComplianceStatus = ComplianceStatus.LEGACY_CLASSICAL_VULNERABLE
    shor_susceptible: bool = False
    grover_susceptible: bool = False
    
    classical_vulnerability: float = 0.0
    quantum_vulnerability: float = 0.0
    
    asset_criticality: float = 1.0
    data_shelf_life: float = 1.0
    individual_qri: float = 0.0
    uncertainty_score: float = 0.0
    
    owasp_category: Optional[str] = None
    reason: Optional[str] = None
    deprecation_deadline: Optional[str] = None
    audit_gaps: List[AuditGap] = Field(default_factory=list)
    remediation: Optional[Dict[str, Any]] = None


class StandardComplianceReport(BaseModel):
    is_valid: bool = True
    spec_version: str = "1.6"
    bom_format: str = "CycloneDX"
    total_components: int = 0
    crypto_components_count: int = 0
    schema_errors: List[str] = Field(default_factory=list)
    adherence_score: float = 100.0
    taxonomy_coverage: Dict[str, int] = Field(default_factory=dict)
    audit_gaps_total: int = 0
    summary_notes: List[str] = Field(default_factory=list)


class QRIOverallResult(BaseModel):
    overall_score: float = 0.0
    risk_level: str = "SAFE"
    confidence_score: float = 100.0
    total_crypto_assets: int = 0
    safe_count: int = 0
    classical_vulnerable_count: int = 0
    broken_count: int = 0
    hybrid_count: int = 0
    audit_gaps_count: int = 0
    hndl_exposure_index: float = 0.0
    breakdown_by_family: Dict[str, int] = Field(default_factory=dict)


class RemediationDirective(BaseModel):
    asset_id: str
    asset_name: str
    component_name: str
    current_algorithm: str
    recommended_replacement: str
    nist_standard: str
    hybrid_alternative: Optional[str] = None
    priority_tier: str
    deprecation_deadline: str
    public_key_overhead: Optional[str] = None
    ciphertext_overhead: Optional[str] = None
    action_plan: str


class ComparisonDelta(BaseModel):
    baseline_file: str
    target_file: str
    baseline_qri: float
    target_qri: float
    qri_delta: float
    risk_reduction_percent: float
    resolved_vulnerabilities: List[str] = Field(default_factory=list)
    new_vulnerabilities: List[str] = Field(default_factory=list)
    remediated_count: int = 0
    remaining_count: int = 0
    summary: str


class AnalysisReport(BaseModel):
    tool_name: str = "QuantumPulse"
    version: str = "1.0.0"
    timestamp: str
    manifest_name: str
    standard_compliance: StandardComplianceReport
    qri_summary: QRIOverallResult
    assets: List[CryptographicAsset] = Field(default_factory=list)
    directives: List[RemediationDirective] = Field(default_factory=list)
