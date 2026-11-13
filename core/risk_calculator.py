"""
QuantumPulse Quantum Risk Index (QRI) & Exposure Calculator
Implements the transparent, deterministic composite risk formula:
QRI = sum(W_alg * V_quantum * C_asset * T_exposure) normalized on a [0-100] scale,
with Harvest-Now-Decrypt-Later (HNDL) exposure modeling and confidence interval calculations.
"""

from typing import List, Tuple
from core.models import (
    CryptographicAsset,
    QRIOverallResult,
    ComplianceStatus,
    AlgorithmFamily,
)


class RiskCalculator:
    def __init__(self):
        # Baseline algorithm weights
        self.W_BROKEN = 8.0
        self.W_ASYMMETRIC_VULNERABLE = 5.0
        self.W_SYMMETRIC_GROVER = 1.8
        self.W_HYBRID = 0.5
        self.W_SAFE = 0.0

    def calculate_qri(self, assets: List[CryptographicAsset]) -> Tuple[QRIOverallResult, List[CryptographicAsset]]:
        """
        Calculates individual asset QRI and system-wide composite QRI
        with confidence intervals.
        """
        if not assets:
            return (
                QRIOverallResult(
                    overall_score=0.0,
                    risk_level="SAFE",
                    confidence_score=100.0,
                    total_crypto_assets=0,
                ),
                [],
            )

        safe_count = 0
        vulnerable_count = 0
        broken_count = 0
        hybrid_count = 0
        audit_gaps_count = 0
        total_uncertainty = 0.0
        family_breakdown = {}
        hndl_exposure_accum = 0.0

        for asset in assets:
            # 1. Determine Algorithmic Baseline Weight (W_alg)
            if asset.compliance_status == ComplianceStatus.BROKEN_INSECURE:
                w_alg = self.W_BROKEN
                broken_count += 1
            elif asset.compliance_status == ComplianceStatus.LEGACY_CLASSICAL_VULNERABLE:
                w_alg = self.W_ASYMMETRIC_VULNERABLE
                vulnerable_count += 1
            elif asset.compliance_status == ComplianceStatus.HYBRID_TRANSITION:
                w_alg = self.W_HYBRID
                hybrid_count += 1
            else:
                w_alg = self.W_SAFE
                safe_count += 1

            # 2. Determine Quantum Susceptibility (V_quantum)
            if asset.shor_susceptible:
                v_quantum = 1.0
            elif asset.grover_susceptible:
                v_quantum = 0.4
            else:
                v_quantum = 0.0

            # 3. Determine Asset Criticality (C_asset)
            c_asset = self._derive_asset_criticality(asset)
            asset.asset_criticality = c_asset

            # 4. Determine Data Shelf-Life / HNDL Horizon (T_exposure)
            t_exposure = self._derive_data_shelf_life(asset)
            asset.data_shelf_life = t_exposure

            # 5. Composite Asset QRI Formula
            # If classically broken, it represents an immediate exploit regardless of quantum timeline
            if asset.compliance_status == ComplianceStatus.BROKEN_INSECURE:
                vuln_factor = max(v_quantum, asset.classical_vulnerability)
            elif asset.compliance_status == ComplianceStatus.COMPLIANT_QUANTUM_SAFE:
                vuln_factor = 0.0
            elif asset.compliance_status == ComplianceStatus.HYBRID_TRANSITION:
                vuln_factor = 0.05
            else:
                vuln_factor = (v_quantum * 0.70) + (asset.classical_vulnerability * 0.30)

            raw_asset_score = w_alg * vuln_factor * c_asset * t_exposure
            # Scale single asset risk to [0, 100]
            # Max possible raw score ~ 8.0 * 1.0 * 3.0 * 2.5 = 60.0
            scaled_asset_qri = min(100.0, round((raw_asset_score / 60.0) * 100.0, 1))
            asset.individual_qri = scaled_asset_qri

            # Accumulate HNDL exposure
            if asset.family in [AlgorithmFamily.KEY_EXCHANGE, AlgorithmFamily.ASYMMETRIC_ENCRYPTION] and asset.shor_susceptible:
                hndl_exposure_accum += (c_asset * t_exposure)

            # Audit gaps and uncertainty
            audit_gaps_count += len(asset.audit_gaps)
            total_uncertainty += asset.uncertainty_score

            # Family breakdown
            fam_key = asset.family.value
            family_breakdown[fam_key] = family_breakdown.get(fam_key, 0) + 1

        # Calculate Overall System Score
        total_assets = len(assets)
        mean_asset_qri = sum(a.individual_qri for a in assets) / total_assets
        max_asset_qri = max(a.individual_qri for a in assets)

        # Composite System QRI: 60% average risk across assets + 40% peak single-asset risk penalty
        overall_score = round(min(100.0, (mean_asset_qri * 0.60) + (max_asset_qri * 0.40)), 1)

        # Risk level determination
        if overall_score <= 15.0 and broken_count == 0:
            risk_level = "SAFE"
        elif overall_score <= 35.0:
            risk_level = "LOW"
        elif overall_score <= 60.0:
            risk_level = "MEDIUM"
        elif overall_score <= 80.0:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        # If any broken primitive exists in an enterprise asset, floor risk level at HIGH
        if broken_count > 0 and overall_score < 65.0:
            overall_score = max(overall_score, 65.0)
            risk_level = "HIGH"

        # Calculate Confidence Score (accounting for missing metadata)
        avg_uncertainty = total_uncertainty / total_assets
        confidence_score = round(max(20.0, min(100.0, 100.0 - (avg_uncertainty * 100.0))), 1)

        # Normalized HNDL exposure index
        hndl_index = round(min(100.0, (hndl_exposure_accum / max(1, total_assets * 3.0)) * 100.0), 1)

        qri_result = QRIOverallResult(
            overall_score=overall_score,
            risk_level=risk_level,
            confidence_score=confidence_score,
            total_crypto_assets=total_assets,
            safe_count=safe_count,
            classical_vulnerable_count=vulnerable_count,
            broken_count=broken_count,
            hybrid_count=hybrid_count,
            audit_gaps_count=audit_gaps_count,
            hndl_exposure_index=hndl_index,
            breakdown_by_family=family_breakdown,
        )

        return qri_result, assets

    def _derive_asset_criticality(self, asset: CryptographicAsset) -> float:
        purpose = (asset.context_purpose or "").lower()
        name = asset.component_name.lower()

        # High Criticality (3.0): Core Financial, Payment, PII, Credential Storage
        if any(k in purpose or k in name for k in ["bank", "payment", "financial", "pin", "password", "credential", "auth"]):
            return 3.0
        # Medium Criticality (2.0): Public TLS, External APIs, VPN
        if any(k in purpose or k in name for k in ["tls", "api", "vpn", "handshake", "web"]):
            return 2.0
        # Low Criticality (1.0): Internal staging, test, file checksum
        if any(k in purpose or k in name for k in ["test", "staging", "checksum", "integrity", "cache"]):
            return 1.0
        return 1.5

    def _derive_data_shelf_life(self, asset: CryptographicAsset) -> float:
        """
        Harvest-Now-Decrypt-Later (HNDL) factor based on data confidentiality horizon.
        Data that must stay secret for >10 years (e.g. healthcare, financial, long-term keys)
        faces the highest urgency today.
        """
        purpose = (asset.context_purpose or "").lower()
        if any(k in purpose for k in ["financial", "pin", "credential", "password", "secret", "data-at-rest"]):
            return 2.5  # Long retention > 10 years
        if any(k in purpose for k in ["tls-handshake", "vpn-tunnel"]):
            return 2.0  # Network traffic recorded today by adversaries
        if any(k in purpose for k in ["jwt", "token", "session"]):
            return 1.2  # Ephemeral tokens
        if any(k in purpose for k in ["file-checksum", "cache"]):
            return 1.0  # No confidentiality value
        return 1.5
