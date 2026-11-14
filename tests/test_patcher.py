"""
Unit tests for CodePatcher module.
"""

from core.patcher import CodePatcher


def test_code_patcher_kem():
    patch = CodePatcher.get_patch_snippet("RSA-2048", "ML-KEM-768", language="python")
    assert patch["language"] == "Python"
    assert "ML-KEM-768" in patch["code"]
    assert "x25519" in patch["code"]
    assert "HKDF" in patch["code"]


def test_code_patcher_signature():
    patch = CodePatcher.get_patch_snippet("ECDSA-P256", "ML-DSA-65", language="python")
    assert "ML-DSA-65" in patch["code"]
    assert "verify" in patch["code"]


def test_code_patcher_symmetric():
    patch = CodePatcher.get_patch_snippet("AES-128", "AES-256-GCM", language="python")
    assert "AESGCM" in patch["code"]
    assert "256" in patch["code"]


def test_code_patcher_openssl():
    patch = CodePatcher.get_patch_snippet("ECDH", "ML-KEM-768", language="openssl")
    assert patch["language"] == "NGINX / OpenSSL"
    assert "X25519MLKEM768" in patch["code"]

