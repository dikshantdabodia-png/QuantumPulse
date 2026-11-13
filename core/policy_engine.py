"""
QuantumPulse Cryptographic Policy and Heuristics Engine
Evaluates normalized cryptographic assets against declarative YAML policies,
applies contextual intent heuristics to eliminate false positives,
and tags items with compliance states and OWASP Top 10 A02 tags.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml
from core.models import (
    CryptographicAsset,
    ComplianceStatus,
    AlgorithmFamily,
)


class PolicyEngine:
    def __init__(self, rules_path: Optional[Path] = None):
        if rules_path is None:
            rules_path = Path(__file__).resolve().parent.parent / "rules" / "pqc_rules.yaml"
        self.rules_config = self._load_rules(rules_path)
        self.algorithms_rules = self.rules_config.get("algorithms", [])
        self.contextual_heuristics = self.rules_config.get("contextual_heuristics", [])
        self.scoring_weights = self.rules_config.get("scoring", {})

    def _load_rules(self, path: Path) -> Dict[str, Any]:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    def evaluate_assets(self, assets: List[CryptographicAsset]) -> List[CryptographicAsset]:
        """Evaluates a list of assets against policy baselines and contextual heuristics."""
        evaluated: List[CryptographicAsset] = []
        for asset in assets:
            ev_asset = self.evaluate_single_asset(asset)
            evaluated.append(ev_asset)
        return evaluated

    def evaluate_single_asset(self, asset: CryptographicAsset) -> CryptographicAsset:
        """Evaluates a single asset against rules and contextual intent."""
        # Find matching rule definition
        matched_rule = self._find_matching_rule(asset)

        if matched_rule:
            self._apply_rule(asset, matched_rule)
        else:
            self._apply_fallback_heuristic(asset)

        # Apply Contextual Intent Heuristics (e.g. MD5 file checksum vs password hash)
        self._apply_contextual_heuristics(asset)

        # Apply Audit Gap Uncertainty Penalty
        if asset.audit_gaps:
            asset.uncertainty_score = min(1.0, len(asset.audit_gaps) * 0.25)
            # If key size was unknown, default to conservative worst-case
            if any("key_size" in g.field_name for g in asset.audit_gaps):
                if asset.family in [AlgorithmFamily.ASYMMETRIC_ENCRYPTION, AlgorithmFamily.DIGITAL_SIGNATURE]:
                    asset.classical_vulnerability = max(asset.classical_vulnerability, 0.7)
                    asset.quantum_vulnerability = 1.0
                elif asset.family == AlgorithmFamily.SYMMETRIC_CIPHER:
                    asset.quantum_vulnerability = max(asset.quantum_vulnerability, 0.3)

        return asset

    def _find_matching_rule(self, asset: CryptographicAsset) -> Optional[Dict[str, Any]]:
        name_upper = asset.name.upper()
        for rule in self.algorithms_rules:
            r_name = rule.get("name", "").upper()
            if r_name == name_upper:
                return rule
            # Check prefix for hybrid or parameter names
            if r_name in name_upper and len(r_name) > 2:
                return rule
        return None

    def _apply_rule(self, asset: CryptographicAsset, rule: Dict[str, Any]):
        sub_rules = rule.get("rules", [])
        if sub_rules:
            # Conditional sub-rule matching based on key_size
            key_size = asset.key_size or 0
            matched_sub = None
            for sub in sub_rules:
                cond = sub.get("condition", "")
                try:
                    # Safe evaluated conditions on key_size
                    if eval(cond, {"__builtins__": {}}, {"key_size": key_size}):
                        matched_sub = sub
                        break
                except Exception:
                    pass
            if not matched_sub and sub_rules:
                matched_sub = sub_rules[0]

            if matched_sub:
                status_str = matched_sub.get("classification", "LEGACY_CLASSICAL_VULNERABLE")
                asset.compliance_status = ComplianceStatus(status_str)
                asset.classical_vulnerability = float(matched_sub.get("classical_vulnerability", 0.0))
                asset.quantum_vulnerability = float(matched_sub.get("quantum_vulnerability", 0.0))
                asset.owasp_category = matched_sub.get("owasp_tag")
                asset.reason = matched_sub.get("reason")
                asset.deprecation_deadline = matched_sub.get("deprecation_deadline")
                asset.shor_susceptible = rule.get("shor_susceptible", False)
                asset.grover_susceptible = rule.get("grover_susceptible", False)
                return

        # Direct rule matching
        status_str = rule.get("classification", "LEGACY_CLASSICAL_VULNERABLE")
        try:
            asset.compliance_status = ComplianceStatus(status_str)
        except ValueError:
            asset.compliance_status = ComplianceStatus.LEGACY_CLASSICAL_VULNERABLE

        asset.classical_vulnerability = float(rule.get("classical_vulnerability", 0.0))
        asset.quantum_vulnerability = float(rule.get("quantum_vulnerability", 0.0))
        asset.shor_susceptible = rule.get("shor_susceptible", False)
        asset.grover_susceptible = rule.get("grover_susceptible", False)
        asset.owasp_category = rule.get("owasp_tag")
        asset.reason = rule.get("reason")
        asset.deprecation_deadline = rule.get("deprecation_deadline", "2030")

    def _apply_fallback_heuristic(self, asset: CryptographicAsset):
        if asset.family in [AlgorithmFamily.PQC_KEM, AlgorithmFamily.PQC_SIGNATURE]:
            asset.compliance_status = ComplianceStatus.COMPLIANT_QUANTUM_SAFE
            asset.classical_vulnerability = 0.0
            asset.quantum_vulnerability = 0.0
            asset.shor_susceptible = False
            asset.grover_susceptible = False
            asset.owasp_category = "Compliant (Post-Quantum Primitive)"
            asset.reason = "Post-quantum standardized algorithm."
            asset.deprecation_deadline = "None"
        elif asset.family == AlgorithmFamily.HYBRID:
            asset.compliance_status = ComplianceStatus.HYBRID_TRANSITION
            asset.classical_vulnerability = 0.0
            asset.quantum_vulnerability = 0.0
            asset.shor_susceptible = False
            asset.grover_susceptible = False
            asset.owasp_category = "Compliant (Hybrid PQC Transition)"
            asset.reason = "Hybrid combination of classical and post-quantum mechanisms."
            asset.deprecation_deadline = "None"
        elif asset.family in [AlgorithmFamily.ASYMMETRIC_ENCRYPTION, AlgorithmFamily.KEY_EXCHANGE, AlgorithmFamily.DIGITAL_SIGNATURE]:
            asset.compliance_status = ComplianceStatus.LEGACY_CLASSICAL_VULNERABLE
            asset.classical_vulnerability = 0.2
            asset.quantum_vulnerability = 1.0
            asset.shor_susceptible = True
            asset.grover_susceptible = False
            asset.owasp_category = "A02:2021-Cryptographic Failures (Classical Asymmetric Shor Target)"
            asset.reason = "Classical asymmetric primitive vulnerable to Shor's algorithm."
            asset.deprecation_deadline = "2030"
        elif asset.family == AlgorithmFamily.SYMMETRIC_CIPHER:
            if asset.key_size and asset.key_size >= 256:
                asset.compliance_status = ComplianceStatus.COMPLIANT_QUANTUM_SAFE
                asset.classical_vulnerability = 0.0
                asset.quantum_vulnerability = 0.0
                asset.shor_susceptible = False
                asset.grover_susceptible = False
                asset.owasp_category = "Compliant (Quantum Resistant Symmetric)"
                asset.reason = "256-bit symmetric cipher resistant to Grover's algorithm."
                asset.deprecation_deadline = "None"
            else:
                asset.compliance_status = ComplianceStatus.COMPLIANT_QUANTUM_SAFE
                asset.classical_vulnerability = 0.0
                asset.quantum_vulnerability = 0.3
                asset.shor_susceptible = False
                asset.grover_susceptible = True
                asset.owasp_category = "Compliant (Grover Halving Advisory)"
                asset.reason = "Symmetric cipher vulnerable to Grover's search speedup."
                asset.deprecation_deadline = "2035"
        elif asset.family == AlgorithmFamily.HASH_DIGEST:
            name_u = asset.name.upper()
            if any(k in name_u for k in ["SHA-256", "SHA-384", "SHA-512", "SHA256", "SHA3", "BLAKE"]):
                asset.compliance_status = ComplianceStatus.COMPLIANT_QUANTUM_SAFE
                asset.classical_vulnerability = 0.0
                asset.quantum_vulnerability = 0.0
                asset.shor_susceptible = False
                asset.grover_susceptible = False
                asset.owasp_category = "Compliant (Secure Hash Primitive)"
                asset.reason = "Cryptographically secure hash function."
                asset.deprecation_deadline = "None"
            else:
                asset.compliance_status = ComplianceStatus.LEGACY_CLASSICAL_VULNERABLE
                asset.classical_vulnerability = 0.5
                asset.quantum_vulnerability = 0.0
                asset.owasp_category = "A02:2021-Cryptographic Failures (Unverified Hash)"
                asset.reason = "Unverified legacy hash function."
                asset.deprecation_deadline = "2030"
        else:
            asset.compliance_status = ComplianceStatus.LEGACY_CLASSICAL_VULNERABLE
            asset.classical_vulnerability = 0.5
            asset.quantum_vulnerability = 0.5
            asset.owasp_category = "A02:2021-Cryptographic Failures (Unclassified Primitive)"
            asset.reason = "Unrecognized algorithm primitive requiring manual review."
            asset.deprecation_deadline = "Review"

    def _apply_contextual_heuristics(self, asset: CryptographicAsset):
        """Processes contextual intent to eliminate false positives on benign non-security hashing."""
        if not asset.context_purpose:
            return

        purpose_lower = asset.context_purpose.lower()
        asset_name_upper = asset.name.upper()

        for heuristic in self.contextual_heuristics:
            match_algos = [a.upper() for a in heuristic.get("match_algorithms", [])]
            match_contexts = [c.lower() for c in heuristic.get("match_contexts", [])]

            if asset_name_upper in match_algos and any(c in purpose_lower for c in match_contexts):
                action = heuristic.get("action")
                if action == "DOWNGRADE_SEVERITY":
                    # Reduce classical vulnerability drastically because it's not a security boundary
                    asset.classical_vulnerability = max(0.05, asset.classical_vulnerability * 0.2)
                    asset.reason = f"{asset.reason or ''} [Heuristic: Context '{asset.context_purpose}' is non-security functional usage; severity downgraded]"
                    asset.owasp_category = "A02:2021-Non-Security Functional Hash (Low Exposure)"
                elif action == "ESCALATE_SEVERITY":
                    asset.compliance_status = ComplianceStatus.BROKEN_INSECURE
                    asset.classical_vulnerability = 1.0
                    asset.reason = f"{asset.reason or ''} [CRITICAL VIOLATION: Broken primitive in '{asset.context_purpose}' context]"
                    asset.owasp_category = "A02:2021-Cryptographic Failures (Critical Broken Primitive in Security Boundary)"
