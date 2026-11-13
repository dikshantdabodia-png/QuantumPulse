"""
QuantumPulse Codebase-to-CBOM Extractor & Generator
Scans source code directories (Python, Java, JavaScript/TypeScript, Go, and X.509 certificates)
to discover cryptographic primitives, libraries, and keys, and synthesizes an official
CycloneDX 1.6 (ECMA-424) Cryptographic Bill of Materials (CBOM).
"""

import re
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class CodebaseCBOMGenerator:
    def __init__(self):
        # Regex patterns for common cryptographic API invocations
        self.patterns = [
            # Python patterns
            (r"hashlib\.md5\(", "MD5", "digest", 128, None, "file-checksum"),
            (r"hashlib\.sha1\(", "SHA-1", "digest", 160, None, "digest"),
            (r"hashlib\.sha256\(", "SHA-256", "digest", 256, None, "digest"),
            (r"hashlib\.sha3_256\(", "SHA3-256", "digest", 256, None, "digest"),
            (r"RSA\.generate\(\s*(\d{3,4})", "RSA", "pke", None, None, "key-generation"),
            (r"AES\.new\(.*AES\.MODE_(\w+)", "AES", "cipher", 128, None, "data-at-rest"),
            (r"Cipher\(algorithms\.AES\([^)]*\),\s*modes\.(\w+)", "AES", "cipher", 256, None, "data-at-rest"),
            (r"ec\.SECP(\d+)R1", "ECDSA", "signature", 256, "secp256r1", "digital-signature"),
            (r"x25519\.X25519PrivateKey", "X25519", "key-agree", 256, "curve25519", "key-exchange"),
            (r"ed25519\.Ed25519PrivateKey", "Ed25519", "signature", 256, "ed25519", "digital-signature"),

            # Java / Kotlin patterns
            (r'Cipher\.getInstance\(\s*["\']AES/(\w+)/', "AES", "cipher", 256, None, "data-at-rest"),
            (r'Cipher\.getInstance\(\s*["\']DESede/', "3DES", "cipher", 168, "CBC", "legacy-transport"),
            (r'Cipher\.getInstance\(\s*["\']DES/', "DES", "cipher", 56, "CBC", "legacy-cipher"),
            (r'MessageDigest\.getInstance\(\s*["\']MD5["\']', "MD5", "digest", 128, None, "hash-digest"),
            (r'MessageDigest\.getInstance\(\s*["\']SHA-1["\']', "SHA-1", "digest", 160, None, "hash-digest"),
            (r'KeyPairGenerator\.getInstance\(\s*["\']RSA["\']', "RSA", "pke", 2048, None, "asymmetric-key"),
            (r'KeyPairGenerator\.getInstance\(\s*["\']EC["\']', "ECDSA", "signature", 256, "secp256r1", "digital-signature"),

            # JavaScript / Node.js patterns
            (r'crypto\.createHash\(\s*["\']md5["\']', "MD5", "digest", 128, None, "hash-digest"),
            (r'crypto\.createHash\(\s*["\']sha1["\']', "SHA-1", "digest", 160, None, "hash-digest"),
            (r'crypto\.createCipheriv\(\s*["\']aes-128-(\w+)["\']', "AES", "cipher", 128, None, "data-at-rest"),
            (r'crypto\.createCipheriv\(\s*["\']aes-256-(\w+)["\']', "AES", "cipher", 256, None, "data-at-rest"),

            # Post-Quantum / Hybrid libraries (liboqs, oqs, pqcrypto, etc.)
            (r"ML-KEM-?(\d{3,4})|mlkem(\d{3,4})", "ML-KEM", "kem", 768, None, "pqc-key-exchange"),
            (r"ML-DSA-?(\d{2})|mldsa(\d{2})", "ML-DSA", "signature", 65, None, "pqc-signature"),
            (r"SLH-DSA|slhdsa", "SLH-DSA", "signature", 128, None, "pqc-signature"),
            (r"X25519\s*\+\s*ML-KEM|X25519MLKEM", "X25519+ML-KEM-768", "kem", 768, "curve25519", "hybrid-handshake"),
        ]

    def scan_directory(self, target_dir: str | Path, app_name: Optional[str] = None) -> Dict[str, Any]:
        """Scans a directory tree and generates a CycloneDX 1.6 CBOM document."""
        root = Path(target_dir)
        if not root.exists():
            raise FileNotFoundError(f"Directory not found: {target_dir}")

        app_name = app_name or root.name or "Discovered-Application"
        components = []
        discovered_keys = set()

        # Extensions to inspect
        valid_exts = {".py", ".java", ".kt", ".js", ".ts", ".go", ".c", ".cpp", ".cs", ".php", ".rb", ".pem", ".crt"}

        for fpath in root.rglob("*"):
            if fpath.is_file() and fpath.suffix.lower() in valid_exts:
                # Skip hidden directories / node_modules / venv
                if any(part.startswith(".") or part in ["node_modules", "venv", "__pycache__", "target", "build", "dist"] for part in fpath.parts):
                    continue
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    self._extract_from_code(content, fpath, components, discovered_keys)
                except Exception:
                    pass

        # If zero discovered, provide minimal generic entry
        if not components:
            components.append({
                "type": "application",
                "name": app_name,
                "version": "1.0.0",
                "description": "Scanned codebase with no explicit cryptographic primitives detected.",
            })

        cbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": {
                    "components": [
                        {
                            "name": "QuantumPulse-Codebase-Scanner",
                            "version": "1.0.0",
                        }
                    ]
                },
                "component": {
                    "type": "application",
                    "name": app_name,
                    "version": "1.0.0",
                },
            },
            "components": components,
        }

        return cbom

    def _extract_from_code(self, content: str, file_path: Path, components: List[Dict[str, Any]], discovered_keys: set):
        for pattern, algo_name, primitive, default_size, default_curve, default_purpose in self.patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            for m in matches:
                # Derive parameter if captured
                param_size = default_size
                mode = None
                curve = default_curve

                if m.groups():
                    val = m.group(1)
                    if val and val.isdigit():
                        param_size = int(val)
                    elif val and val.upper() in ["GCM", "CBC", "CTR", "ECB"]:
                        mode = val.upper()

                unique_key = f"{algo_name}:{param_size}:{mode}:{file_path.name}"
                if unique_key in discovered_keys:
                    continue
                discovered_keys.add(unique_key)

                comp_ref = f"{file_path.stem}#{algo_name.lower()}-{len(components)+1}"
                
                algo_props: Dict[str, Any] = {
                    "primitive": primitive,
                }
                if param_size:
                    algo_props["parameterSetIdentifier"] = param_size
                if curve:
                    algo_props["curve"] = curve
                if mode:
                    algo_props["mode"] = mode

                components.append({
                    "type": "cryptographic-asset",
                    "name": f"{algo_name}{('-' + str(param_size)) if param_size and param_size > 32 else ''}",
                    "bom-ref": comp_ref,
                    "description": f"Discovered in {file_path.name}:{content[:m.start()].count('\n') + 1}",
                    "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": algo_props,
                    },
                    "properties": [
                        {"name": "purpose", "value": default_purpose},
                        {"name": "source_file", "value": str(file_path.name)},
                    ],
                })

