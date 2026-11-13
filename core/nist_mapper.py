"""
QuantumPulse NIST PQC Migration Advisor
Maps legacy and classical-vulnerable primitives directly to finalized NIST Post-Quantum standards:
- FIPS 203: ML-KEM (Module-Lattice Key Encapsulation Mechanism)
- FIPS 204: ML-DSA (Module-Lattice Digital Signature Standard)
- FIPS 205: SLH-DSA (Stateless Hash-Based Digital Signatures)
Provides context-aware migration directives, hybrid crypto recommendations,
quantified performance trade-offs, and prioritized remediation tiers.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml
from core.models import (
    CryptographicAsset,
    RemediationDirective,
    ComplianceStatus,
    AlgorithmFamily,
)


class NISTMigrationAdvisor:
    def __init__(self, catalog_path: Optional[Path] = None):
        if catalog_path is None:
            catalog_path = Path(__file__).resolve().parent.parent / "rules" / "nist_catalog.yaml"
        self.catalog = self._load_catalog(catalog_path)
        self.pqc_standards = self.catalog.get("pqc_standards", {})
        self.baselines = self.catalog.get("classical_baselines", {})
        self.migration_matrix = self.catalog.get("migration_matrix", {})

    def _load_catalog(self, path: Path) -> Dict[str, Any]:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    def generate_advisories(self, assets: List[CryptographicAsset]) -> List[RemediationDirective]:
        """Generates prioritized migration directives for all vulnerable assets."""
        directives: List[RemediationDirective] = []

        for asset in assets:
            if asset.compliance_status in [ComplianceStatus.LEGACY_CLASSICAL_VULNERABLE, ComplianceStatus.BROKEN_INSECURE]:
                directive = self.advise_asset(asset)
                if directive:
                    directives.append(directive)
                    asset.remediation = directive.model_dump()

        # Sort directives by priority tier (Tier 1 first) then deadline
        tier_order = {"Tier 1 (Immediate)": 1, "Tier 2 (By 2030)": 2, "Tier 3 (By 2035)": 3}
        directives.sort(key=lambda d: tier_order.get(d.priority_tier, 4))
        return directives

    def advise_asset(self, asset: CryptographicAsset) -> Optional[RemediationDirective]:
        name_upper = asset.name.upper()
        fam = asset.family

        # 1. Asymmetric Encryption / Key Exchange (HNDL Threat) -> ML-KEM
        if fam in [AlgorithmFamily.KEY_EXCHANGE, AlgorithmFamily.ASYMMETRIC_ENCRYPTION]:
            return self._advise_kem(asset)

        # 2. Digital Signatures -> ML-DSA or SLH-DSA
        if fam == AlgorithmFamily.DIGITAL_SIGNATURE:
            return self._advise_signature(asset)

        # 3. Symmetric Ciphers (Broken or Grover) -> AES-256-GCM
        if fam == AlgorithmFamily.SYMMETRIC_CIPHER:
            return self._advise_symmetric(asset)

        # 4. Hash Functions (MD5, SHA-1) -> SHA-256 or SHA3-256
        if fam == AlgorithmFamily.HASH_DIGEST:
            return self._advise_hash(asset)

        return None

    def _advise_kem(self, asset: CryptographicAsset) -> RemediationDirective:
        is_high_assurance = asset.asset_criticality >= 3.0
        target = "ML-KEM-1024" if is_high_assurance else "ML-KEM-768"
        sec_level = "5" if is_high_assurance else "3"
        
        # Calculate size deltas
        pubkey_delta = "+1,152 bytes (vs X25519 32B)" if "25519" in asset.name else "+928 bytes (vs RSA-2048 256B)"
        ciphertext_delta = "1,088 bytes ciphertext"
        
        priority_tier = "Tier 1 (Immediate)"
        action_plan = (
            f"Replace legacy key exchange with {target} (NIST FIPS 203, Level {sec_level}). "
            f"For TLS 1.3 or IKEv2 network channels, adopt the hybrid wrapper 'X25519+{target}' "
            "to guarantee backward compatibility while eliminating Harvest-Now-Decrypt-Later (HNDL) vulnerability."
        )

        return RemediationDirective(
            asset_id=asset.id,
            asset_name=asset.name,
            component_name=asset.component_name,
            current_algorithm=f"{asset.name}{('-' + str(asset.key_size)) if asset.key_size else ''}",
            recommended_replacement=target,
            nist_standard="NIST FIPS 203 (ML-KEM)",
            hybrid_alternative=f"X25519+{target}",
            priority_tier=priority_tier,
            deprecation_deadline="Immediate (HNDL Active Exposure)",
            public_key_overhead=pubkey_delta,
            ciphertext_overhead=ciphertext_delta,
            action_plan=action_plan,
        )

    def _advise_signature(self, asset: CryptographicAsset) -> RemediationDirective:
        is_root_ca_or_firmware = any(k in (asset.context_purpose or "").lower() for k in ["root", "ca", "firmware", "archive"])
        
        if is_root_ca_or_firmware:
            target = "SLH-DSA-SHA2-128s"
            standard = "NIST FIPS 205 (SLH-DSA / SPHINCS+)"
            pubkey_delta = "32 bytes public key"
            sig_delta = "7,856 bytes signature (Stateful hash tree)"
            action_plan = (
                "For long-lived root trust anchors or firmware verification, migrate to SLH-DSA-SHA2-128s. "
                "Because it relies purely on SHA-2 hash security with zero lattice assumptions, it hedges against theoretical lattice cryptanalysis."
            )
        else:
            target = "ML-DSA-65"
            standard = "NIST FIPS 204 (ML-DSA / Dilithium)"
            pubkey_delta = "1,952 bytes public key (+1,888B vs ECDSA-P256)"
            sig_delta = "3,309 bytes signature (~51.7x size expansion vs ECDSA)"
            action_plan = (
                f"Migrate signature primitive to {target} (NIST FIPS 204 Level 3). "
                "Ensure network buffers, X.509 cert chains, and JWT payload parsers accommodate the 3.3 KB signature size."
            )

        priority_tier = "Tier 1 (Immediate)" if asset.compliance_status == ComplianceStatus.BROKEN_INSECURE else "Tier 2 (By 2030)"
        deadline = asset.deprecation_deadline or "2030"

        return RemediationDirective(
            asset_id=asset.id,
            asset_name=asset.name,
            component_name=asset.component_name,
            current_algorithm=f"{asset.name}{('-' + str(asset.key_size)) if asset.key_size else ''}",
            recommended_replacement=target,
            nist_standard=standard,
            hybrid_alternative=f"{asset.name}+{target} Dual-Certificate Chain",
            priority_tier=priority_tier,
            deprecation_deadline=deadline,
            public_key_overhead=pubkey_delta,
            ciphertext_overhead=sig_delta,
            action_plan=action_plan,
        )

    def _advise_symmetric(self, asset: CryptographicAsset) -> RemediationDirective:
        if asset.name in ["DES", "3DES", "RC4"]:
            priority = "Tier 1 (Immediate)"
            deadline = "Immediate"
            action_plan = (
                f"Discontinue broken cipher {asset.name} immediately. "
                "Migrate to AES-256-GCM (NIST SP 800-38D) to achieve 128-bit quantum security against Grover's algorithm and eliminate Sweet32 block collisions."
            )
        else:
            # AES-128
            priority = "Tier 3 (By 2035)"
            deadline = "2035"
            action_plan = (
                "Upgrade key length from AES-128 to AES-256-GCM. "
                "Under Grover's quantum search algorithm, AES-128's effective security drops to 64 bits, whereas AES-256 retains 128 bits of quantum security."
            )

        return RemediationDirective(
            asset_id=asset.id,
            asset_name=asset.name,
            component_name=asset.component_name,
            current_algorithm=f"{asset.name}{('-' + str(asset.key_size)) if asset.key_size else ''}",
            recommended_replacement="AES-256-GCM",
            nist_standard="NIST SP 800-38D / CNSA 2.0",
            hybrid_alternative=None,
            priority_tier=priority,
            deprecation_deadline=deadline,
            public_key_overhead="N/A (Symmetric)",
            ciphertext_overhead="16 bytes GCM Auth Tag",
            action_plan=action_plan,
        )

    def _advise_hash(self, asset: CryptographicAsset) -> RemediationDirective:
        target = "SHA3-256" if asset.asset_criticality >= 2.5 else "SHA-256"
        std = "FIPS 202 (SHA-3)" if "SHA3" in target else "FIPS 180-4 (SHA-2)"
        
        priority = "Tier 1 (Immediate)" if asset.compliance_status == ComplianceStatus.BROKEN_INSECURE else "Tier 2 (By 2030)"
        action_plan = (
            f"Replace vulnerable hash {asset.name} with {target}. "
            f"Eliminates practical collision attacks and conforms to NIST SP 800-131A Rev. 2 guidelines."
        )

        return RemediationDirective(
            asset_id=asset.id,
            asset_name=asset.name,
            component_name=asset.component_name,
            current_algorithm=asset.name,
            recommended_replacement=target,
            nist_standard=std,
            hybrid_alternative=None,
            priority_tier=priority,
            deprecation_deadline="Immediate",
            public_key_overhead="N/A",
            ciphertext_overhead=f"256-bit ({'32' if '256' in target else '64'} bytes) digest",
            action_plan=action_plan,
        )

