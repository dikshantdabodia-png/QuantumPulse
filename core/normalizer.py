"""
QuantumPulse Canonical Algorithm & OID Normalizer
Transforms raw strings, OIDs, and variant nomenclatures from diverse CBOM generators
into uniform, structured cryptographic objects.
"""

import re
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import yaml
from core.models import AlgorithmFamily


class CanonicalNormalizer:
    def __init__(self, oids_path: Optional[Path] = None):
        if oids_path is None:
            oids_path = Path(__file__).resolve().parent.parent / "rules" / "oids.yaml"
        self.oids_map = self._load_oids(oids_path)
        
        # Curve alias dictionary
        self.curve_aliases = {
            "prime256v1": "secp256r1",
            "nist p-256": "secp256r1",
            "p-256": "secp256r1",
            "nist p-384": "secp384r1",
            "p-384": "secp384r1",
            "nist p-521": "secp521r1",
            "p-521": "secp521r1",
            "edwards25519": "ed25519",
            "curve25519": "x25519",
        }

    def _load_oids(self, path: Path) -> Dict[str, Any]:
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    return data.get("oids", {})
            except Exception:
                return {}
        return {}

    def normalize(
        self,
        raw_name: str,
        raw_oid: Optional[str] = None,
        raw_key_size: Optional[int] = None,
        raw_curve: Optional[str] = None,
        raw_mode: Optional[str] = None,
        raw_primitive: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Normalizes any naming variant, OID, or fragment into a canonical dictionary:
        {
            'name': 'RSA',
            'family': AlgorithmFamily.ASYMMETRIC_ENCRYPTION,
            'key_size': 2048,
            'curve': None,
            'mode': None,
            'oid': '1.2.840.113549.1.1.1'
        }
        """
        name = (raw_name or "").strip()
        oid = raw_oid.strip() if raw_oid else None
        key_size = raw_key_size
        curve = raw_curve.strip() if raw_curve else None
        mode = raw_mode.strip().upper() if raw_mode else None
        family = AlgorithmFamily.UNKNOWN

        # 1. Check OID database if OID is provided
        if oid and oid in self.oids_map:
            oid_info = self.oids_map[oid]
            name = oid_info.get("name", name)
            if not key_size and "key_size" in oid_info:
                key_size = oid_info["key_size"]
            if not mode and "mode" in oid_info:
                mode = oid_info["mode"]

        cleaned = name.upper().replace("_", "-").replace(" ", "-")

        # 2. Check for Hybrid Primitives first
        if "HYBRID" in cleaned or ("ML-KEM" in cleaned and ("X25519" in cleaned or "P256" in cleaned)):
            family = AlgorithmFamily.HYBRID
            return {
                "name": "X25519+ML-KEM-768",
                "family": family,
                "key_size": key_size or 768,
                "curve": "curve25519",
                "mode": mode,
                "oid": oid,
            }

        # 3. Check for Post-Quantum Algorithms (NIST FIPS 203/204/205)
        if "ML-KEM" in cleaned or "KYBER" in cleaned:
            family = AlgorithmFamily.PQC_KEM
            if "1024" in cleaned:
                canonical_name = "ML-KEM-1024"
                key_size = 1024
            elif "512" in cleaned:
                canonical_name = "ML-KEM-512"
                key_size = 512
            else:
                canonical_name = "ML-KEM-768"
                key_size = 768
            return {
                "name": canonical_name,
                "family": family,
                "key_size": key_size,
                "curve": None,
                "mode": mode,
                "oid": oid,
            }

        if "ML-DSA" in cleaned or "DILITHIUM" in cleaned:
            family = AlgorithmFamily.PQC_SIGNATURE
            if "87" in cleaned or "5" in cleaned:
                canonical_name = "ML-DSA-87"
            elif "44" in cleaned or "2" in cleaned:
                canonical_name = "ML-DSA-44"
            else:
                canonical_name = "ML-DSA-65"
            return {
                "name": canonical_name,
                "family": family,
                "key_size": key_size or 65,
                "curve": None,
                "mode": mode,
                "oid": oid,
            }

        if "SLH-DSA" in cleaned or "SPHINCS" in cleaned:
            family = AlgorithmFamily.PQC_SIGNATURE
            return {
                "name": "SLH-DSA",
                "family": family,
                "key_size": key_size,
                "curve": None,
                "mode": mode,
                "oid": oid,
            }

        # 4. Check for RSA variations
        if "RSA" in cleaned:
            # Extract key size if present in name (e.g., RSA-2048, RSA2048)
            match = re.search(r"RSA-?(\d{3,4})", cleaned)
            if match:
                key_size = int(match.group(1))
            
            # Determine family
            if "SIGN" in cleaned or "PSS" in cleaned or "SHA" in cleaned:
                family = AlgorithmFamily.DIGITAL_SIGNATURE
            else:
                family = AlgorithmFamily.ASYMMETRIC_ENCRYPTION

            return {
                "name": "RSA",
                "family": family,
                "key_size": key_size,
                "curve": None,
                "mode": mode,
                "oid": oid or ("1.2.840.113549.1.1.1" if not "PSS" in cleaned else "1.2.840.113549.1.1.10"),
            }

        # 5. Check for ECC / ECDSA / ECDH
        if "ECDSA" in cleaned or "EC-DSA" in cleaned:
            family = AlgorithmFamily.DIGITAL_SIGNATURE
            curve = self._extract_curve(cleaned, curve)
            key_size = self._derive_curve_bits(curve) or key_size
            return {
                "name": "ECDSA",
                "family": family,
                "key_size": key_size,
                "curve": curve,
                "mode": mode,
                "oid": oid or "1.2.840.10045.2.1",
            }

        if "ECDH" in cleaned or "EC-DH" in cleaned:
            family = AlgorithmFamily.KEY_EXCHANGE
            curve = self._extract_curve(cleaned, curve)
            key_size = self._derive_curve_bits(curve) or key_size
            return {
                "name": "ECDH",
                "family": family,
                "key_size": key_size,
                "curve": curve,
                "mode": mode,
                "oid": oid,
            }

        if "ED25519" in cleaned:
            return {
                "name": "Ed25519",
                "family": AlgorithmFamily.DIGITAL_SIGNATURE,
                "key_size": 256,
                "curve": "ed25519",
                "mode": mode,
                "oid": oid or "1.3.101.112",
            }

        if "X25519" in cleaned or "CURVE25519" in cleaned:
            return {
                "name": "X25519",
                "family": AlgorithmFamily.KEY_EXCHANGE,
                "key_size": 256,
                "curve": "x25519",
                "mode": mode,
                "oid": oid or "1.3.101.110",
            }

        if cleaned == "DH" or "DIFFIE-HELLMAN" in cleaned:
            return {
                "name": "DH",
                "family": AlgorithmFamily.KEY_EXCHANGE,
                "key_size": key_size,
                "curve": None,
                "mode": mode,
                "oid": oid,
            }

        # 6. Check for Symmetric Ciphers (AES, 3DES, DES, RC4, ChaCha20)
        if "AES" in cleaned:
            family = AlgorithmFamily.SYMMETRIC_CIPHER
            match = re.search(r"AES-?(\d{3})", cleaned)
            if match:
                key_size = int(match.group(1))
            mode_match = re.search(r"(GCM|CBC|CTR|ECB|CFB|OFB|CCM)", cleaned)
            if mode_match and not mode:
                mode = mode_match.group(1)
            return {
                "name": "AES",
                "family": family,
                "key_size": key_size or 128,
                "curve": None,
                "mode": mode or "GCM",
                "oid": oid,
            }

        if "3DES" in cleaned or "DES-EDE" in cleaned or "TRIPLE-DES" in cleaned:
            return {
                "name": "3DES",
                "family": AlgorithmFamily.SYMMETRIC_CIPHER,
                "key_size": 168,
                "curve": None,
                "mode": mode or "CBC",
                "oid": oid or "1.2.840.113549.3.7",
            }

        if cleaned == "DES":
            return {
                "name": "DES",
                "family": AlgorithmFamily.SYMMETRIC_CIPHER,
                "key_size": 56,
                "curve": None,
                "mode": mode or "CBC",
                "oid": oid,
            }

        if "RC4" in cleaned or "ARCFOUR" in cleaned:
            return {
                "name": "RC4",
                "family": AlgorithmFamily.SYMMETRIC_CIPHER,
                "key_size": key_size or 128,
                "curve": None,
                "mode": mode,
                "oid": oid,
            }

        if "CHACHA20" in cleaned:
            return {
                "name": "ChaCha20",
                "family": AlgorithmFamily.SYMMETRIC_CIPHER,
                "key_size": 256,
                "curve": None,
                "mode": mode or "Poly1305",
                "oid": oid,
            }

        # 7. Check for Hash Primitives (MD5, SHA-1, SHA-2, SHA-3)
        if "MD5" in cleaned:
            return {
                "name": "MD5",
                "family": AlgorithmFamily.HASH_DIGEST,
                "key_size": 128,
                "curve": None,
                "mode": None,
                "oid": oid or "1.2.840.113549.2.5",
            }

        if "SHA-1" in cleaned or "SHA1" in cleaned:
            return {
                "name": "SHA-1",
                "family": AlgorithmFamily.HASH_DIGEST,
                "key_size": 160,
                "curve": None,
                "mode": None,
                "oid": oid or "1.3.14.3.2.26",
            }

        if "SHA3" in cleaned or "SHA-3" in cleaned:
            bits = 256
            if "512" in cleaned:
                bits = 512
            elif "384" in cleaned:
                bits = 384
            return {
                "name": f"SHA3-{bits}",
                "family": AlgorithmFamily.HASH_DIGEST,
                "key_size": bits,
                "curve": None,
                "mode": None,
                "oid": oid,
            }

        if "SHA-256" in cleaned or "SHA256" in cleaned:
            return {
                "name": "SHA-256",
                "family": AlgorithmFamily.HASH_DIGEST,
                "key_size": 256,
                "curve": None,
                "mode": None,
                "oid": oid or "2.16.840.1.101.3.4.2.1",
            }

        if "SHA-384" in cleaned or "SHA384" in cleaned:
            return {
                "name": "SHA-384",
                "family": AlgorithmFamily.HASH_DIGEST,
                "key_size": 384,
                "curve": None,
                "mode": None,
                "oid": oid or "2.16.840.1.101.3.4.2.2",
            }

        if "SHA-512" in cleaned or "SHA512" in cleaned:
            return {
                "name": "SHA-512",
                "family": AlgorithmFamily.HASH_DIGEST,
                "key_size": 512,
                "curve": None,
                "mode": None,
                "oid": oid or "2.16.840.1.101.3.4.2.3",
            }

        # Fallback
        return {
            "name": name or "UNKNOWN",
            "family": family,
            "key_size": key_size,
            "curve": curve,
            "mode": mode,
            "oid": oid,
        }

    def _extract_curve(self, cleaned: str, current_curve: Optional[str]) -> Optional[str]:
        if current_curve:
            normalized = current_curve.lower()
            return self.curve_aliases.get(normalized, current_curve)
        
        for alias, canonical in self.curve_aliases.items():
            if alias.upper().replace(" ", "-") in cleaned:
                return canonical
        if "SECP256R1" in cleaned or "P256" in cleaned:
            return "secp256r1"
        if "SECP384R1" in cleaned or "P384" in cleaned:
            return "secp384r1"
        if "SECP521R1" in cleaned or "P521" in cleaned:
            return "secp521r1"
        if "SECP256K1" in cleaned:
            return "secp256k1"
        return None

    def _derive_curve_bits(self, curve: Optional[str]) -> Optional[int]:
        if not curve:
            return None
        c = curve.lower()
        if "256" in c or "25519" in c:
            return 256
        if "384" in c:
            return 384
        if "521" in c or "448" in c:
            return 521
        return None

