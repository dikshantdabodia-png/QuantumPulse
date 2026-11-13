# QuantumPulse: Phased Development Roadmap

**Project:** QuantumPulse — CBOM File Analyzer and PQC Migration Advisor  
**Standard:** CycloneDX 1.6+ (ECMA-424)  
**NIST PQC Targets:** FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), NIST SP 800-131A Rev. 2, CNSA 2.0  

---

## Phased Execution Plan & Status

- [x] **Phase 0: Project Scaffolding, Schemas & Dependencies**
  - Set up directory structure (`core/`, `cli/`, `gui/`, `rules/`, `schemas/`, `samples/`, `tests/`, `benchmarks/`).
  - Configured `requirements.txt` with locked dependencies.
  - Set up external rule definitions (`rules/pqc_rules.yaml`, `rules/nist_catalog.yaml`, `rules/oids.yaml`).
  - Embedded official CycloneDX 1.6 schema in `schemas/cyclonedx-1.6.json`.

- [x] **Phase 1: CBOM Ingestion, CycloneDX Standard Comparer & Canonical Normalization**
  - Data models (`core/models.py`) with Pydantic for components, crypto assets, certificates, and protocols.
  - JSON schema validator and resilient parser (`core/parser.py`) with Audit Gap detection (graceful fallback for missing fields).
  - **CycloneDX Standard Comparer (`core/cyclonedx_validator.py`)**: Compares user-ingested CBOM against CycloneDX 1.6 / ECMA-424 standards, verifying taxonomy completeness, mandatory fields, and spec compliance.
  - Canonical normalizer (`core/normalizer.py`) for algorithm names and OIDs.
  - Generated multiple realistic sample CBOM files in `samples/` (Enterprise Banking, PQC Cloud Microservice, Hybrid VPN, Legacy Shadow-IT, Incomplete Edge Case).

- [x] **Phase 2: Cryptographic Policy & Heuristics Engine**
  - Declarative policy evaluator (`core/policy_engine.py`) using YAML rules.
  - Contextual intent heuristics (distinguishing benign non-security hashes from critical security usages).
  - Tagging: `COMPLIANT_QUANTUM_SAFE`, `LEGACY_CLASSICAL_VULNERABLE`, `BROKEN_INSECURE`, `HYBRID_TRANSITION`.
  - OWASP Top 10:2021 A02 mapping.

- [x] **Phase 3: Quantum Risk Index (QRI) & Exposure Calculator**
  - Transparent formula: $QRI = \sum (W_{alg} \times V_{quantum} \times C_{asset} \times T_{exposure})$ on [0–100] scale.
  - "Harvest Now, Decrypt Later" (HNDL) data shelf-life horizon scaling.
  - Confidence interval / uncertainty estimation for incomplete metadata.

- [x] **Phase 4: NIST PQC Remediation & Migration Advisory Engine**
  - Algorithm replacement mapping to FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA).
  - Context-aware recommendations (TLS handshake vs data-at-rest / signatures).
  - Quantified performance trade-offs (key sizes, ciphertext expansion, performance overhead).
  - Hybrid cryptography guidance and prioritized timeline deadlines (2030, 2033, 2035).

- [x] **Phase 5: CBOM Comparison & Multi-Format Reporting**
  - CBOM delta comparison engine (`core/cbom_comparer.py`) for migration progress tracking across versions.
  - Exporters (`core/reporter.py`) for JSON, SARIF (CI/CD security gates), Markdown, and executive PDF reports (ReportLab).

- [x] **Phase 6: Terminal CLI Suite**
  - Typer CLI (`cli/main.py`) powered by Rich tables, colored risk badges, tree views, and CI/CD exit codes.

- [x] **Phase 7: Interactive Web GUI Dashboard**
  - Streamlit dashboard (`gui/dashboard.py`) with drag-and-drop upload, KPI cards, Plotly charts, audit inventory table, migration advisor tab, comparison view, and 1-click PDF download.

- [x] **Phase 8: Benchmarks, Synthetic Generator & Automated Testing**
  - Synthetic dataset generator (`benchmarks/generate_synthetic.py`).
  - Pytest test suite with high coverage (17 passing tests).
  - Performance benchmarks (`benchmarks/run_benchmark.py` measuring latency/memory across 10 to 5,000+ assets: ~1,650 assets/sec).

- [x] **Phase 9: Industry Value-Add: Built-in Codebase-to-CBOM Generator (`core/generator.py`)**
  - Built-in scanner to scan codebase directories, configs, and certificate files directly to auto-generate a valid CycloneDX 1.6 CBOM.
  - Final comprehensive `README.md` with complete documentation, architecture diagrams, and industrial usage guide.
