"""
Unit tests for CodebaseCBOMGenerator and Synthetic Benchmark Suite.
"""

from pathlib import Path
from core.generator import CodebaseCBOMGenerator
from benchmarks.generate_synthetic import generate_synthetic_cbom
from core.parser import CBOMParser


def test_codebase_generator_on_core():
    gen = CodebaseCBOMGenerator()
    cbom = gen.scan_directory("core", app_name="QuantumPulse-Core")
    
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert len(cbom["components"]) > 0

    # Ingest through parser to ensure valid CycloneDX 1.6
    parser = CBOMParser()
    compliance, assets = parser.parse_data(cbom, manifest_name="scanned_core.json")
    assert compliance.is_valid is True
    assert len(assets) > 0


def test_synthetic_cbom_generation():
    manifest = generate_synthetic_cbom(num_assets=50, app_name="Test-Synthetic")
    assert manifest["bomFormat"] == "CycloneDX"
    assert len(manifest["components"]) == 50

    parser = CBOMParser()
    compliance, assets = parser.parse_data(manifest, manifest_name="synth_50.json")
    assert compliance.is_valid is True
    assert len(assets) == 50


def test_is_github_url_detection():
    gen = CodebaseCBOMGenerator()
    assert gen.is_github_url("https://github.com/owner/repo") is True
    assert gen.is_github_url("https://github.com/owner/repo.git") is True
    assert gen.is_github_url("http://github.com/test/app") is True
    assert gen.is_github_url("git@github.com:owner/repo.git") is True
    assert gen.is_github_url("core") is False
    assert gen.is_github_url("C:/path/to/folder") is False
    assert gen.is_github_url("/usr/local/src") is False

