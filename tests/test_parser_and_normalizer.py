"""
Tests for Phase 1: CBOM Parser, CycloneDX Standard Comparer, and Canonical Normalizer.
"""

from pathlib import Path
import pytest
from core.parser import CBOMParser
from core.normalizer import CanonicalNormalizer
from core.models import ComplianceStatus, AlgorithmFamily


@pytest.fixture
def parser():
    return CBOMParser()


@pytest.fixture
def normalizer():
    return CanonicalNormalizer()


def test_normalizer_rsa_variants(normalizer):
    res1 = normalizer.normalize("RSA_2048")
    assert res1["name"] == "RSA"
    assert res1["key_size"] == 2048
    assert res1["family"] == AlgorithmFamily.ASYMMETRIC_ENCRYPTION

    res2 = normalizer.normalize("RSA-4096-SIGN")
    assert res2["name"] == "RSA"
    assert res2["key_size"] == 4096
    assert res2["family"] == AlgorithmFamily.DIGITAL_SIGNATURE


def test_normalizer_oid_lookup(normalizer):
    res = normalizer.normalize(raw_name="UNKNOWN", raw_oid="1.2.840.113549.1.1.1")
    assert res["name"] == "RSA"
    assert res["oid"] == "1.2.840.113549.1.1.1"

    res_sha1 = normalizer.normalize(raw_name="", raw_oid="1.3.14.3.2.26")
    assert res_sha1["name"] == "SHA-1"
    assert res_sha1["family"] == AlgorithmFamily.HASH_DIGEST


def test_normalizer_pqc_and_hybrid(normalizer):
    res_kem = normalizer.normalize("Kyber-768")
    assert res_kem["name"] == "ML-KEM-768"
    assert res_kem["family"] == AlgorithmFamily.PQC_KEM

    res_dsa = normalizer.normalize("Dilithium3")
    assert res_dsa["name"] == "ML-DSA-65"
    assert res_dsa["family"] == AlgorithmFamily.PQC_SIGNATURE

    res_hybrid = normalizer.normalize("X25519+ML-KEM-768")
    assert res_hybrid["name"] == "X25519+ML-KEM-768"
    assert res_hybrid["family"] == AlgorithmFamily.HYBRID


def test_parse_enterprise_banking(parser):
    path = Path("samples/enterprise_banking_cbom.json")
    compliance, assets = parser.parse_file(path)
    
    assert compliance.is_valid is True
    assert compliance.spec_version == "1.6"
    assert compliance.total_components == 6
    assert len(assets) == 6
    
    names = [a.name for a in assets]
    assert "RSA" in names
    assert "3DES" in names
    assert "AES" in names
    assert "SHA-1" in names
    assert "MD5" in names


def test_parse_cloud_pqc(parser):
    path = Path("samples/cloud_microservice_pqc_cbom.json")
    compliance, assets = parser.parse_file(path)
    
    assert compliance.is_valid is True
    assert len(assets) == 4
    kem_asset = next(a for a in assets if a.name == "ML-KEM-768")
    assert kem_asset.family == AlgorithmFamily.PQC_KEM
    assert kem_asset.key_size == 768


def test_parse_hybrid_vpn(parser):
    path = Path("samples/hybrid_vpn_gateway_cbom.json")
    compliance, assets = parser.parse_file(path)
    
    assert compliance.is_valid is True
    hybrid = next(a for a in assets if a.name == "X25519+ML-KEM-768")
    assert hybrid.family == AlgorithmFamily.HYBRID


def test_parse_incomplete_metadata_audit_gaps(parser):
    path = Path("samples/incomplete_metadata_cbom.json")
    compliance, assets = parser.parse_file(path)
    
    # Check that incomplete metadata produces Audit Gaps rather than crashing
    assert len(assets) == 3
    rsa_asset = next(a for a in assets if a.name == "RSA")
    assert len(rsa_asset.audit_gaps) >= 1
    assert any("parameterSetIdentifier" in g.field_name for g in rsa_asset.audit_gaps)


def test_corrupt_json_graceful_handling(parser, tmp_path):
    bad_file = tmp_path / "corrupted.json"
    bad_file.write_text("{ \"bomFormat\": \"CycloneDX\", invalid_json... }", encoding="utf-8")
    
    compliance, assets = parser.parse_file(bad_file)
    assert compliance.is_valid is False
    assert len(assets) == 0
    assert "JSON Syntax Error" in compliance.schema_errors[0]

