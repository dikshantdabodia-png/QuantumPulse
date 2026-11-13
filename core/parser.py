"""
QuantumPulse CBOM Ingestion & Parsing Engine
Parses CycloneDX 1.6 / ECMA-424 JSON manifests, validates against standard schema,
flags Audit Gaps gracefully, and normalizes components into CryptographicAsset models.
"""

import json
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from core.models import CryptographicAsset, StandardComplianceReport, AuditGap, AlgorithmFamily
from core.normalizer import CanonicalNormalizer
from core.cyclonedx_validator import CycloneDXStandardValidator


class CBOMParser:
    def __init__(
        self,
        schema_path: Optional[Path] = None,
        oids_path: Optional[Path] = None,
    ):
        self.validator = CycloneDXStandardValidator(schema_path)
        self.normalizer = CanonicalNormalizer(oids_path)

    def parse_file(self, file_path: str | Path) -> Tuple[StandardComplianceReport, List[CryptographicAsset]]:
        """Parses a CBOM JSON file and returns compliance report + normalized assets."""
        path = Path(file_path)
        if not path.exists():
            report = StandardComplianceReport(
                is_valid=False,
                bom_format="Missing",
                spec_version="Unknown",
                schema_errors=[f"File not found: {path}"],
                adherence_score=0.0,
            )
            return report, []

        try:
            with open(path, "r", encoding="utf-8") as f:
                raw_json = json.load(f)
        except json.JSONDecodeError as e:
            report = StandardComplianceReport(
                is_valid=False,
                bom_format="Invalid JSON",
                spec_version="Unknown",
                schema_errors=[f"JSON Syntax Error on line {e.lineno}, col {e.colno}: {e.msg}"],
                adherence_score=0.0,
            )
            return report, []
        except Exception as e:
            report = StandardComplianceReport(
                is_valid=False,
                bom_format="Error",
                spec_version="Unknown",
                schema_errors=[f"Failed to read file: {str(e)}"],
                adherence_score=0.0,
            )
            return report, []

        return self.parse_data(raw_json, manifest_name=path.name)

    def parse_data(self, data: Dict[str, Any], manifest_name: str = "manifest.json") -> Tuple[StandardComplianceReport, List[CryptographicAsset]]:
        """Parses a loaded dictionary adhering to CycloneDX specifications."""
        compliance_report = self.validator.validate_and_compare(data)
        components = data.get("components", [])
        assets: List[CryptographicAsset] = []

        for idx, comp in enumerate(components):
            c_type = comp.get("type", "")
            crypto_props = comp.get("cryptoProperties", {})
            name = comp.get("name", f"asset-{idx}")
            bom_ref = comp.get("bom-ref", f"ref-{idx}")
            
            # Treat either explicit cryptographic-asset or components containing cryptoProperties
            if c_type == "cryptographic-asset" or crypto_props:
                asset = self._extract_crypto_asset(comp, idx, manifest_name)
                assets.append(asset)
            else:
                # Also inspect generic components that might have crypto clues
                name_upper = name.upper()
                if any(k in name_upper for k in ["RSA", "AES", "ECDSA", "ECDH", "SHA", "MD5", "TLS", "PQC"]):
                    asset = self._extract_crypto_asset(comp, idx, manifest_name)
                    assets.append(asset)

        return compliance_report, assets

    def _extract_crypto_asset(self, comp: Dict[str, Any], index: int, manifest_name: str) -> CryptographicAsset:
        name = comp.get("name", f"asset-{index}")
        c_type = comp.get("type", "cryptographic-asset")
        bom_ref = comp.get("bom-ref", f"{manifest_name}#comp-{index}")
        crypto_props = comp.get("cryptoProperties", {})
        algo_props = crypto_props.get("algorithmProperties", {})
        cert_props = crypto_props.get("certificateProperties", {})
        proto_props = crypto_props.get("protocolProperties", {})
        rel_props = crypto_props.get("relatedCryptoMaterialProperties", {})
        
        raw_oid = crypto_props.get("oid") or algo_props.get("oid")
        raw_key_size = algo_props.get("parameterSetIdentifier") or rel_props.get("size")
        
        # Try converting string parameterSetIdentifier to int if applicable
        parsed_key_size: Optional[int] = None
        if raw_key_size is not None:
            try:
                parsed_key_size = int(raw_key_size)
            except (ValueError, TypeError):
                parsed_key_size = None

        raw_curve = algo_props.get("curve")
        raw_mode = algo_props.get("mode")
        raw_primitive = algo_props.get("primitive")
        padding = algo_props.get("padding")

        # Extract context or purpose from custom properties
        context_purpose = None
        properties = comp.get("properties", [])
        for prop in properties:
            p_name = prop.get("name", "").lower()
            if p_name in ["purpose", "context", "usage", "intent"]:
                context_purpose = prop.get("value", "").lower()
                break

        # Protocol specific extraction
        if proto_props:
            context_purpose = context_purpose or "tls-handshake"
            proto_type = proto_props.get("type", "protocol")
            proto_ver = proto_props.get("version", "")
            if not name or name == f"asset-{index}":
                name = f"{proto_type}-{proto_ver}".upper()

        # Certificate specific extraction
        if cert_props:
            context_purpose = context_purpose or "certificate-identity"

        # Canonical normalization
        norm = self.normalizer.normalize(
            raw_name=name,
            raw_oid=raw_oid,
            raw_key_size=parsed_key_size,
            raw_curve=raw_curve,
            raw_mode=raw_mode,
            raw_primitive=raw_primitive,
        )

        # Audit Gap Detection
        audit_gaps: List[AuditGap] = []
        if norm["name"] in ["RSA", "AES", "3DES", "DES"] and not norm["key_size"]:
            audit_gaps.append(
                AuditGap(
                    field_name="parameterSetIdentifier / key_size",
                    description=f"Missing key length for {norm['name']}; unable to precisely verify classical security level.",
                    impact="High",
                )
            )
        if norm["name"] == "AES" and not norm["mode"]:
            audit_gaps.append(
                AuditGap(
                    field_name="algorithmProperties.mode",
                    description="Missing operational mode (e.g. GCM vs ECB/CBC) for AES cipher.",
                    impact="Medium",
                )
            )
        if not context_purpose:
            audit_gaps.append(
                AuditGap(
                    field_name="component.properties.purpose",
                    description="Cryptographic operational context/purpose unspecified; evaluated under baseline security intent.",
                    impact="Low",
                )
            )

        asset = CryptographicAsset(
            id=f"CA-{index+1:04d}",
            name=norm["name"],
            raw_name=name,
            oid=norm["oid"],
            family=norm["family"],
            primitive=raw_primitive or ("cipher" if norm["family"] == AlgorithmFamily.SYMMETRIC_CIPHER else None),
            key_size=norm["key_size"],
            curve=norm["curve"],
            mode=norm["mode"],
            padding=padding,
            component_name=comp.get("description") or comp.get("name") or "Component",
            component_type=c_type,
            bom_ref=bom_ref,
            context_purpose=context_purpose,
            audit_gaps=audit_gaps,
        )

        return asset

