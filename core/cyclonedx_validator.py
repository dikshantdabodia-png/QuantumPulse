"""
QuantumPulse CycloneDX Standard Comparer & Validator
Evaluates an ingested file against official CycloneDX 1.6 / ECMA-424 specifications,
checking structural validity, taxonomy coverage, and calculating a Standards Adherence Score.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import jsonschema
from core.models import StandardComplianceReport


class CycloneDXStandardValidator:
    def __init__(self, schema_path: Optional[Path] = None):
        if schema_path is None:
            schema_path = Path(__file__).resolve().parent.parent / "schemas" / "cyclonedx-1.6.json"
        self.schema = self._load_schema(schema_path)

    def _load_schema(self, path: Path) -> Dict[str, Any]:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def validate_and_compare(self, manifest_data: Dict[str, Any]) -> StandardComplianceReport:
        """
        Validates the raw parsed JSON against the official CycloneDX 1.6 schema
        and audits compliance with ECMA-424 cryptographic taxonomy standards.
        """
        schema_errors: List[str] = []
        summary_notes: List[str] = []
        taxonomy_coverage = {
            "algorithm": 0,
            "certificate": 0,
            "protocol": 0,
            "related-crypto-material": 0,
            "generic-component": 0,
        }
        audit_gaps = 0
        adherence_points = 100.0

        # 1. Structural JSON Schema Validation
        if self.schema:
            validator = jsonschema.Draft7Validator(self.schema)
            errors = list(validator.iter_errors(manifest_data))
            for err in errors[:10]:  # limit to first 10 for readability
                path = " -> ".join([str(p) for p in err.path]) or "root"
                schema_errors.append(f"[{path}] {err.message}")
            if errors:
                adherence_points -= min(40.0, len(errors) * 5.0)

        # 2. CycloneDX Header Standards Evaluation
        bom_format = manifest_data.get("bomFormat", "Missing")
        spec_version = str(manifest_data.get("specVersion", "Missing"))
        serial_number = manifest_data.get("serialNumber")
        metadata = manifest_data.get("metadata", {})

        if bom_format != "CycloneDX":
            adherence_points -= 20.0
            summary_notes.append("Standard violation: 'bomFormat' must be 'CycloneDX'.")

        if spec_version not in ["1.4", "1.5", "1.6"]:
            adherence_points -= 15.0
            summary_notes.append(f"Standard violation: 'specVersion' ({spec_version}) is not a supported CycloneDX standard.")
        elif spec_version != "1.6":
            adherence_points -= 5.0
            summary_notes.append(f"Recommendation: Upgrade from CycloneDX {spec_version} to 1.6 (ECMA-424) for full cryptographic registry support.")

        if not serial_number:
            adherence_points -= 5.0
            summary_notes.append("Recommendation: Missing 'serialNumber' URN for manifest traceability.")

        if not metadata.get("timestamp"):
            adherence_points -= 5.0
            summary_notes.append("Audit Gap: Manifest metadata missing 'timestamp'.")

        # 3. Component & ECMA-424 Cryptographic Taxonomy Evaluation
        components = manifest_data.get("components", [])
        total_components = len(components)
        crypto_components = 0

        for comp in components:
            c_type = comp.get("type")
            crypto_props = comp.get("cryptoProperties")

            if crypto_props or c_type == "cryptographic-asset":
                crypto_components += 1
                asset_type = crypto_props.get("assetType", "unknown") if crypto_props else "unknown"
                if asset_type in taxonomy_coverage:
                    taxonomy_coverage[asset_type] += 1
                else:
                    taxonomy_coverage["algorithm"] += 1

                # Check ECMA-424 recommended crypto attributes
                if crypto_props:
                    algo_props = crypto_props.get("algorithmProperties", {})
                    if not algo_props.get("primitive"):
                        audit_gaps += 1
                    if not algo_props.get("parameterSetIdentifier") and not algo_props.get("curve"):
                        audit_gaps += 1
            else:
                taxonomy_coverage["generic-component"] += 1

        if crypto_components == 0:
            adherence_points -= 20.0
            summary_notes.append("Warning: Manifest contains no cryptographic-asset components or cryptoProperties extensions.")

        # Deduct small penalty for missing crypto details
        if audit_gaps > 0:
            deduction = min(15.0, audit_gaps * 1.5)
            adherence_points -= deduction
            summary_notes.append(f"Identified {audit_gaps} missing cryptographic attribute fields (Audit Gaps) across assets.")

        adherence_score = max(0.0, min(100.0, round(adherence_points, 1)))
        is_valid = len(schema_errors) == 0 and bom_format == "CycloneDX"

        return StandardComplianceReport(
            is_valid=is_valid,
            spec_version=spec_version,
            bom_format=bom_format,
            total_components=total_components,
            crypto_components_count=crypto_components,
            schema_errors=schema_errors,
            adherence_score=adherence_score,
            taxonomy_coverage=taxonomy_coverage,
            audit_gaps_total=audit_gaps,
            summary_notes=summary_notes,
        )
