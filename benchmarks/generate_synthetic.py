"""
QuantumPulse Synthetic CBOM Dataset Generator
Generates realistic enterprise-scale CycloneDX 1.6 (ECMA-424) CBOM JSON manifests
with configurable asset counts (10 to 5,000+) and crypto-sprawl distributions.
"""

import json
import random
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional


ALGORITHM_POOL = [
    # Classical Asymmetric (Shor-vulnerable)
    {"name": "RSA", "primitive": "pke", "key_sizes": [1024, 2048, 3072, 4096], "modes": [None], "curves": [None], "purposes": ["tls-handshake", "payment-transport", "vpn-key-exchange"]},
    {"name": "ECDSA", "primitive": "signature", "key_sizes": [256, 384], "modes": [None], "curves": ["secp256r1", "secp384r1", "secp256k1"], "purposes": ["jwt-signing", "code-signing", "auth-token"]},
    {"name": "ECDH", "primitive": "key-agree", "key_sizes": [256], "modes": [None], "curves": ["secp256r1", "secp384r1"], "purposes": ["tls-handshake", "vpn-tunnel"]},
    {"name": "Ed25519", "primitive": "signature", "key_sizes": [256], "modes": [None], "curves": ["ed25519"], "purposes": ["ssh-identity", "api-signing"]},
    {"name": "X25519", "primitive": "key-agree", "key_sizes": [256], "modes": [None], "curves": ["curve25519"], "purposes": ["tls-handshake", "wireguard-handshake"]},

    # Symmetric Ciphers
    {"name": "AES", "primitive": "cipher", "key_sizes": [128, 192, 256], "modes": ["GCM", "CBC", "CTR"], "curves": [None], "purposes": ["data-at-rest", "session-transport", "database-encryption"]},
    {"name": "ChaCha20", "primitive": "cipher", "key_sizes": [256], "modes": ["Poly1305"], "curves": [None], "purposes": ["mobile-transport", "packet-encryption"]},
    {"name": "3DES", "primitive": "cipher", "key_sizes": [168], "modes": ["CBC"], "curves": [None], "purposes": ["atm-pin-encryption", "legacy-core"]},
    {"name": "DES", "primitive": "cipher", "key_sizes": [56], "modes": ["CBC"], "curves": [None], "purposes": ["legacy-script"]},
    {"name": "RC4", "primitive": "cipher", "key_sizes": [128], "modes": [None], "curves": [None], "purposes": ["legacy-stream"]},

    # Hash Functions
    {"name": "SHA-256", "primitive": "digest", "key_sizes": [256], "modes": [None], "curves": [None], "purposes": ["payload-integrity", "hmac-auth"]},
    {"name": "SHA3-256", "primitive": "digest", "key_sizes": [256], "modes": [None], "curves": [None], "purposes": ["audit-logging", "content-hash"]},
    {"name": "SHA-1", "primitive": "digest", "key_sizes": [160], "modes": [None], "curves": [None], "purposes": ["git-commit", "legacy-sig"]},
    {"name": "MD5", "primitive": "digest", "key_sizes": [128], "modes": [None], "curves": [None], "purposes": ["file-checksum", "cache-key", "password-hash"]},

    # Post-Quantum & Hybrid
    {"name": "ML-KEM-768", "primitive": "kem", "key_sizes": [768], "modes": [None], "curves": [None], "purposes": ["tls-handshake", "pqc-session"]},
    {"name": "ML-DSA-65", "primitive": "signature", "key_sizes": [65], "modes": [None], "curves": [None], "purposes": ["pqc-token-signing", "pqc-ca"]},
    {"name": "X25519+ML-KEM-768", "primitive": "kem", "key_sizes": [768], "modes": [None], "curves": ["curve25519"], "purposes": ["hybrid-handshake"]},
]


def generate_synthetic_cbom(
    num_assets: int = 100,
    app_name: str = "Enterprise-Synthetic-System",
    output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Generates a synthetic CBOM with specified asset count and realistic attributes."""
    components = []

    for i in range(num_assets):
        template = random.choice(ALGORITHM_POOL)
        key_size = random.choice(template["key_sizes"])
        mode = random.choice(template["modes"])
        curve = random.choice(template["curves"])
        purpose = random.choice(template["purposes"])

        algo_props: Dict[str, Any] = {
            "primitive": template["primitive"],
        }
        if key_size:
            algo_props["parameterSetIdentifier"] = key_size
        if mode:
            algo_props["mode"] = mode
        if curve:
            algo_props["curve"] = curve

        comp = {
            "type": "cryptographic-asset",
            "name": f"{template['name']}{('-' + str(key_size)) if key_size and key_size > 32 else ''}",
            "bom-ref": f"synth-app#asset-{i+1:05d}",
            "description": f"Microservice component #{i // 5 + 1} cryptographic wrapper",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": algo_props,
            },
            "properties": [
                {"name": "purpose", "value": purpose},
                {"name": "service_id", "value": f"svc-{(i % 25) + 1:02d}"},
            ],
        }
        components.append(comp)

    manifest = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "name": "QuantumPulse-Synthetic-Generator",
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

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return manifest


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate synthetic CycloneDX CBOM files.")
    parser.add_argument("--count", type=int, default=500, help="Number of cryptographic assets.")
    parser.add_argument("--output", type=str, default="samples/synthetic_500_assets.json", help="Output path.")
    args = parser.parse_args()

    generate_synthetic_cbom(num_assets=args.count, output_path=Path(args.output))
    print(f"Generated synthetic CBOM with {args.count} assets at {args.output}")
