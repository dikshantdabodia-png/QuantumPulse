# 🛡️ QuantumPulse

**Cryptographic Bill of Materials (CBOM) Analyzer & NIST Post-Quantum Cryptography (PQC) Migration Advisor**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Standard](https://img.shields.io/badge/CycloneDX-1.6%20(ECMA--424)-green.svg)](https://cyclonedx.org/capabilities/cbom/)
[![NIST Standards](https://img.shields.io/badge/NIST-FIPS%20203%20%7C%20204%20%7C%20205-purple.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![OS: Linux | Windows | macOS](https://img.shields.io/badge/OS-Kali%20Linux%20%7C%20Ubuntu%20%7C%20macOS%20%7C%20Windows-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-17%20passed-brightgreen.svg)]()

---

## 📖 Table of Contents
1. [Overview & Core Value Proposition](#-overview--core-value-proposition)
2. [Why Industry Needs QuantumPulse (Key Benefits)](#-why-industry-needs-quantumpulse-key-benefits)
3. [Quickstart Guide (Linux / Kali Linux / macOS / Windows)](#-quickstart-guide-linux--kali-linux--macos--windows)
4. [Running the Command Line Interface (CLI)](#-running-the-command-line-interface-cli)
5. [Running the Interactive Web GUI Dashboard](#-running-the-interactive-web-gui-dashboard)
6. [Codebase-to-CBOM Scanner (Solving the Industry Generation Gap)](#-codebase-to-cbom-scanner-solving-the-industry-generation-gap)
7. [NIST Post-Quantum Cryptography Standards Alignment](#-nist-post-quantum-cryptography-standards-alignment)
8. [Mathematical Formulation: Quantum Risk Index (QRI)](#-mathematical-formulation-quantum-risk-index-qri)
9. [CI/CD SDLC Governance Gates (SARIF Integration)](#-cicd-sdlc-governance-gates-sarif-integration)
10. [Performance Benchmarks](#-performance-benchmarks)
11. [Troubleshooting & Verification](#-troubleshooting--verification)

---

## 🌟 Overview & Core Value Proposition

**QuantumPulse** is an enterprise-grade cryptographic governance, risk modeling, and post-quantum migration platform. As cryptographically relevant quantum computers (CRQCs) approach reality, classical public-key cryptography (RSA, ECC, Diffie-Hellman) will be rendered obsolete by Shor's algorithm. 

Adversaries are actively executing the **"Harvest Now, Decrypt Later" (HNDL)** attack model: capturing encrypted enterprise network traffic and intellectual property today to decrypt retroactively once quantum hardware matures.

Rather than relying on primitive regular-expression source code scrapers that trigger massive false-positive noise, QuantumPulse establishes a **governance-first architecture**:
1. It ingests machine-readable **Cryptographic Bills of Materials (CBOMs)** serialized in the international **CycloneDX 1.6 (ECMA-424)** standard.
2. It audits algorithm primitives, operational modes, key lengths, and certificate lifetimes against declarative compliance rules.
3. It computes a mathematically grounded **Quantum Risk Index (QRI)** $[0 - 100]$ incorporating data shelf-life horizons.
4. It maps legacy primitives directly to the finalized **NIST Post-Quantum Standards (FIPS 203, FIPS 204, FIPS 205)** with quantified key size and latency overheads.
5. It offers both a **developer-friendly Terminal CLI (Typer + Rich)** and a **CISO Web GUI Dashboard (Streamlit + Plotly)** with **1-click executive PDF export**.

---

## 🎯 Why Industry Needs QuantumPulse (Key Benefits)

| Enterprise Liability | Legacy Approach (SAST / Regex) | QuantumPulse Solution |
| :--- | :--- | :--- |
| **Crypto-Sprawl & Shadow IT** | Security teams lack a structured inventory of active algorithms, certificate chains, and key lengths across microservices. | Ingests or generates standardized **CycloneDX 1.6 (ECMA-424)** CBOMs, creating a centralized, machine-readable cryptographic inventory. |
| **False-Positive Noise** | Primitive regex scanners flag benign file integrity hashes (e.g., non-security MD5/SHA-1 in logging/ETags) with the same severity as password storage. | **Contextual Intent Heuristics:** Automatically evaluates operational wrappers; benign non-security caches are downgraded to Low, while authentication boundaries escalate to Critical. |
| **Harvest Now, Decrypt Later (HNDL)** | Organizations treat quantum risk as a problem for 2035+, ignoring that data intercepted today will be retroactively decrypted. | **HNDL Horizon Modeling:** Prioritizes key exchange protocols (ECDH, RSA transport) and long shelf-life data (>10 years) for **Tier 1 Immediate Remediation**. |
| **Lack of CBOM Tooling in Enterprise** | Most corporate repositories do not yet have automated CBOM pipelines or commercial scanners installed. | **Built-in Codebase Scanner ([`core/generator.py`](file:///d:/Antigravity/QuantumPulse/core/generator.py)):** Scans Python, Java, JS/TS, Go, and X.509 certs to synthesize a CycloneDX 1.6 CBOM directly from any directory. |
| **Audit-Gap Fragility** | Real-world manifests often have incomplete metadata (missing key sizes or modes); legacy parsers crash with validation errors. | **Zero-Crash Resilience:** Tags unverified fields as *Audit Gaps* and calculates a transparent *Analysis Confidence Score* $[0\% - 100\%]$. |
| **Abstract vs. Concrete Guidance** | Traditional tools output vague warnings like "Upgrade RSA" without actionable engineering steps or performance trade-offs. | **Exact NIST FIPS 203/204/205 Mapping:** Quantifies exact public key growth (e.g., $+1,888$ bytes for ML-DSA-65) and recommends hybrid transition wrappers (`X25519+ML-KEM-768`). |
| **Executive & Regulatory Pressure** | CISOs struggle to justify post-quantum budgets to boards and lack automated compliance reporting for US Executive Order 14028 / CNSA 2.0. | Generates **1-Click Executive PDF Reports** with risk gauges, posture tiering, and compliance scores, alongside machine-readable **SARIF** for CI/CD gates. |

---

## 🚀 Quickstart Guide (Linux / Kali Linux / macOS / Windows)

QuantumPulse is designed to be **cloned and executed immediately on ANY operating system**—including **Kali Linux**, Ubuntu, Debian, macOS, and Windows.

### 🐧 Running on Linux (Kali Linux, Ubuntu, Debian)

On Kali Linux or modern Debian/Ubuntu, Python environments are managed via virtual environments (`PEP 668`). Follow these standard steps in your terminal:

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/QuantumPulse.git
cd QuantumPulse

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# (Optional) Install QuantumPulse as a global terminal command:
pip install -e .

# 4. Verify the installation (all 17 unit tests should pass)
python3 -m pytest tests/
```

### 🪟 Running on Windows (PowerShell / Command Prompt)

```powershell
# 1. Clone the repository
git clone https://github.com/<your-username>/QuantumPulse.git
cd QuantumPulse

# 2. Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify test suite
python -m pytest tests/
```

---

## 💻 Running the Command Line Interface (CLI)

The CLI is powered by **Typer** and **Rich** to provide colorful terminal tables, executive risk panels, and CI/CD gate exit codes.

### 1. Basic Manifest Scan (Terminal Rich Mode)
Scan any CycloneDX CBOM file and view the colored interactive inventory:
```bash
python cli/main.py scan samples/enterprise_banking_cbom.json
```
*(If installed with `pip install -e .`, you can simply run: `quantumpulse scan samples/enterprise_banking_cbom.json`)*

**Sample Output Highlights:**
- **Executive Posture Card:** Displays overall Quantum Risk Index (e.g., `65.9 / 100 - HIGH`), CycloneDX Standard Adherence (`100%`), and HNDL Exposure Index.
- **Asset Inventory Table:** ID, canonical algorithm name, key size, operational context, and compliance status.
- **NIST Migration Directives:** Step-by-step target replacements (ML-KEM-768, ML-DSA-65, AES-256-GCM), priority tiers, and deadlines.

---

### 2. Export Audit-Ready Executive PDF Report
Generate a complete executive PDF document with tables, badges, and remediation plans:
```bash
python cli/main.py scan samples/enterprise_banking_cbom.json --format pdf --output banking_audit.pdf
```

---

### 3. CI/CD Governance Gate Mode (Automated Pipeline Failure)
Enforce cryptographic governance in continuous integration pipelines. Block pull requests if deprecated algorithms are introduced:
```bash
# Fails with exit code 1 if any broken primitives (DES, 3DES, MD5) exist
python cli/main.py scan manifest.json --fail-on-broken

# Fails with exit code 3 if overall QRI exceeds threshold of 50.0
python cli/main.py scan manifest.json --max-qri 50.0

# Export findings to SARIF format for GitHub Code Scanning tab
python cli/main.py scan manifest.json --format sarif --output results.sarif
```

---

### 4. Compare Two CBOMs (Migration Delta & Risk Reduction)
Compare a pre-migration baseline against an upgraded target to prove cryptographic risk reduction:
```bash
python cli/main.py compare samples/enterprise_banking_cbom.json samples/cloud_microservice_pqc_cbom.json
```
**Output:** Calculates exact risk reduction percentage (e.g., `-100.0% Risk Reduction`), lists all eliminated legacy algorithms, and tallies remaining vulnerabilities.

---

### 5. Inspect the Cryptographic Policy Registry
View all active algorithm rules, Shor/Grover vulnerability flags, and deprecation deadlines:
```bash
python cli/main.py rules
```

---

### 6. Run Empirical Stress Benchmarks
Benchmark parsing and policy evaluation throughput across small to massive enterprise datasets (10 to 5,000+ assets):
```bash
python cli/main.py benchmark --counts 10,100,500,1000,2500
```

---

## 🌐 Running the Interactive Web GUI Dashboard

Launch the browser-based executive dashboard powered by **Streamlit** and **Plotly**:

```bash
streamlit run gui/dashboard.py
```
*Note: If running on a remote headless Kali Linux or cloud server over SSH, launch with:*
```bash
streamlit run gui/dashboard.py --server.headless true --server.port 8501 --server.address 0.0.0.0
```
Then open `http://localhost:8501` (or `http://<server-ip>:8501`) in your browser.

### 🌟 GUI Dashboard Features:
1. **Sample Loader & File Uploader:** 
   - 1-click loading of any of the **5 included enterprise sample CBOMs** from the sidebar dropdown.
   - Or drag-and-drop your own custom `.json` CBOM file.
2. **Executive Overview Tab:**
   - **Interactive Plotly Speedometer Gauge:** Instant visual posture tiering (Safe, Low, Medium, High, Critical).
   - **Cryptographic Taxonomy Sunburst/Pie Chart:** Distribution of algorithms across families (Asymmetric, Symmetric, Hash, PQC, Hybrid).
   - **HNDL Threat Index & Confidence Cards.**
3. **Cryptographic Inventory Tab:**
   - Filterable, searchable table of all discovered primitives.
   - Filter by status (`COMPLIANT_QUANTUM_SAFE`, `LEGACY_CLASSICAL_VULNERABLE`, `BROKEN_INSECURE`, `HYBRID_TRANSITION`).
4. **NIST PQC Migration Advisor Tab:**
   - Side-by-side **Performance Trade-Off Bar Chart** comparing key size growth and signature/ciphertext expansion.
   - Actionable engineering directives cards with copyable migration directives.
5. **CycloneDX ECMA-424 Compliance Tab:**
   - Standards Adherence Rating ($0 - 100\%$) and taxonomy coverage audit.
6. **Reports & Exports Center:**
   - **1-Click Download Executive PDF Report** (generated dynamically via ReportLab).
   - **Download SARIF v2.1.0** (for GitHub/GitLab security tabs).
   - **Download JSON & Markdown.**
7. **Migration Progress Delta Mode:**
   - Select baseline vs. post-remediation CBOMs to visualize side-by-side risk score reduction and remediated algorithms.

---

## 🔍 Codebase-to-CBOM Scanner (Solving the Industry Generation Gap)

If an enterprise does not have a commercial CBOM generator installed, QuantumPulse includes an internal scanner ([`core/generator.py`](file:///d:/Antigravity/QuantumPulse/core/generator.py)) that inspects codebases and certificate directories directly:

```bash
# Scan a source directory, generate CycloneDX 1.6 CBOM, and immediately run PQC audit:
python cli/main.py generate ./my_source_code -o my_cbom.json --scan
```

### Supported Languages & Patterns:
- **Python:** `cryptography`, `hashlib`, `pycryptodome`, `ssl`
- **Java / Kotlin:** `java.security`, `javax.crypto` (e.g., `Cipher.getInstance("AES/CBC/PKCS5Padding")`, `KeyPairGenerator`)
- **JavaScript / Node.js:** `crypto`, `bcrypt`, `jsonwebtoken`
- **Go:** `crypto/rsa`, `crypto/aes`, `crypto/ecdsa`, `crypto/sha256`
- **X.509 Certificates:** PEM and CRT files

---

## 🏛️ NIST Post-Quantum Cryptography Standards Alignment

QuantumPulse is built strictly upon the **finalized August 2024 NIST Post-Quantum Standards**:

```mermaid
flowchart LR
    subgraph Legacy ["Classical Vulnerable Primitives"]
        RSA["RSA-2048 / RSA-4096\n(Integer Factorization)"]
        ECC["ECDSA / ECDH / Ed25519\n(Discrete Log / ECDLP)"]
        Sym128["AES-128 / 3DES\n(Grover Halving / Sweet32)"]
    end

    subgraph NIST2024 ["NIST Final PQC Standards (2024)"]
        FIPS203["NIST FIPS 203\nML-KEM (Kyber)\nKey Encapsulation"]
        FIPS204["NIST FIPS 204\nML-DSA (Dilithium)\nDigital Signatures"]
        FIPS205["NIST FIPS 205\nSLH-DSA (SPHINCS+)\nStateless Hash Signatures"]
        AES256["NIST SP 800-38D\nAES-256-GCM\n128-bit Quantum Security"]
    end

    RSA -->|Key Exchange| FIPS203
    ECC -->|Key Agreement| FIPS203
    RSA -->|Signatures| FIPS204
    ECC -->|Signatures| FIPS204
    ECC -.->|Root CA / Firmware| FIPS205
    Sym128 -->|Symmetric Upgrade| AES256
```

---

## 🔬 Mathematical Formulation: Quantum Risk Index (QRI)

The platform calculates a deterministic, transparent **Quantum Risk Index (QRI)**:

$$\text{Asset QRI} = W_{\text{alg}} \times V_{\text{quantum}} \times C_{\text{asset}} \times T_{\text{exposure}}$$

$$\text{System QRI} = \min\left(100.0, \, \left(\frac{1}{N} \sum_{i=1}^N \text{Asset QRI}_i \times 0.60\right) + \left(\max_i(\text{Asset QRI}_i) \times 0.40\right)\right)$$

- **$W_{\text{alg}}$:** Algorithmic vulnerability weight ($8.0$ for broken, $5.0$ for Shor-vulnerable, $1.8$ for Grover-affected, $0.0$ for quantum-safe).
- **$V_{\text{quantum}}$:** Susceptibility to Shor's algorithm ($1.0$), Grover search ($0.4$), or Safe ($0.0$). Classically broken primitives evaluate to $1.0$.
- **$C_{\text{asset}}$:** Enterprise criticality rating ($3.0$ for financial/PII, $2.0$ for public TLS/VPN, $1.0$ for internal test).
- **$T_{\text{exposure}}$:** Data shelf-life / HNDL factor ($2.5$ for long-term secret data $>10$ years, $2.0$ for recorded network traffic, $1.0$ for non-sensitive cache).

---

## 🔄 CI/CD SDLC Governance Gates (SARIF Integration)

QuantumPulse integrates natively into **GitHub Actions** and **GitLab CI** to enforce "Shift-Left" cryptographic governance.

### Example GitHub Actions Workflow (`.github/workflows/quantumpulse-gate.yml`):
```yaml
name: QuantumPulse PQC Security Gate

on: [push, pull_request]

jobs:
  pqc-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install QuantumPulse
        run: pip install -r requirements.txt

      - name: Scan CBOM & Fail on Policy Violation
        run: |
          python cli/main.py scan samples/enterprise_banking_cbom.json \
            --format sarif --output results.sarif \
            --fail-on-broken --max-qri 60.0

      - name: Upload SARIF to GitHub Security Tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## ⚡ Performance Benchmarks

Empirical performance evaluation across synthetic enterprise manifests:

| Cryptographic Assets | Total Latency | Processing Throughput | Peak RAM Footprint |
| :---: | :---: | :---: | :---: |
| **10 assets** | 0.0079 s | **1,265 assets/sec** | 0.07 MB |
| **100 assets** | 0.0621 s | **1,609 assets/sec** | 0.43 MB |
| **500 assets** | 0.2920 s | **1,712 assets/sec** | 2.13 MB |
| **1,000 assets** | 0.6071 s | **1,647 assets/sec** | 4.34 MB |
| **2,500 assets** | 1.4812 s | **1,688 assets/sec** | 10.82 MB |
| **5,000 assets** | 2.9430 s | **1,698 assets/sec** | 21.65 MB |

---

## 🛠️ Troubleshooting & Verification

- **How do I verify the test suite?**  
  Run `python -m pytest tests/ -v`. All 17 unit tests should complete in $\sim 1.2$ seconds.
- **Why do I see an Audit Gap warning?**  
  If an ingested CBOM lacks parameter sets (e.g., an RSA entry without specifying whether it is 1024 or 2048-bit), QuantumPulse logs an *Audit Gap* rather than crashing, defaulting to a conservative worst-case risk evaluation and lowering the analysis confidence score.
- **Can I update cryptographic rules without modifying code?**  
  Yes! All rules, thresholds, and deprecation dates are stored declaratively in [`rules/pqc_rules.yaml`](file:///d:/Antigravity/QuantumPulse/rules/pqc_rules.yaml), [`rules/nist_catalog.yaml`](file:///d:/Antigravity/QuantumPulse/rules/nist_catalog.yaml), and [`rules/oids.yaml`](file:///d:/Antigravity/QuantumPulse/rules/oids.yaml).
