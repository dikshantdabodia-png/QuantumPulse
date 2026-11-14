"""
QuantumPulse Interactive Web GUI Dashboard
Built with Streamlit, Plotly, and ReportLab.
Provides an executive dashboard for CBOM analysis, NIST PQC migration tracking,
performance trade-off visualizers, and 1-click audit-ready PDF export.
"""

import sys
import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# Ensure QuantumPulse root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.analyzer import QuantumPulseAnalyzer
from core.cbom_comparer import CBOMComparer
from core.reporter import Reporter
from core.generator import CodebaseCBOMGenerator
from core.patcher import CodePatcher
from core.models import ComplianceStatus, AlgorithmFamily, AnalysisReport


st.set_page_config(
    page_title="QuantumPulse | CBOM Analyzer & PQC Advisor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling
st.markdown(
    """
    <style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #1E3A8A, #3B82F6, #06B6D4);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0px;
    }
    .metric-card {
        background-color: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        padding: 15px;
        text-align: center;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 8px 16px;
        border-radius: 6px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_analyzer():
    return QuantumPulseAnalyzer()


def render_qri_gauge(score: float, level: str):
    """Generates an executive Plotly gauge for Quantum Risk Index."""
    color_map = {
        "SAFE": "#10B981",
        "LOW": "#06B6D4",
        "MEDIUM": "#F59E0B",
        "HIGH": "#F97316",
        "CRITICAL": "#EF4444",
    }
    bar_color = color_map.get(level, "#3B82F6")

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": f"<b>Quantum Risk Index (QRI)</b><br><span style='color:{bar_color}; font-size:16px;'>{level} POSTURE</span>", "font": {"size": 18}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#94A3B8"},
                "bar": {"color": bar_color, "thickness": 0.28},
                "bgcolor": "white",
                "borderwidth": 1,
                "bordercolor": "#E2E8F0",
                "steps": [
                    {"range": [0, 15], "color": "#ECFDF5"},
                    {"range": [15, 35], "color": "#ECFEFF"},
                    {"range": [35, 60], "color": "#FEF3C7"},
                    {"range": [60, 80], "color": "#FFEDD5"},
                    {"range": [80, 100], "color": "#FEE2E2"},
                ],
                "threshold": {
                    "line": {"color": "#DC2626", "width": 4},
                    "thickness": 0.75,
                    "value": score,
                },
            },
        )
    )
    fig.update_layout(height=280, margin=dict(l=20, r=20, t=40, b=10))
    return fig


def main():
    analyzer = get_analyzer()

    # Sidebar Navigation & Input Controls
    st.sidebar.markdown("## 🛡️ QuantumPulse")
    st.sidebar.caption("CBOM Policy Analyzer & NIST PQC Migration Advisor")
    st.sidebar.markdown("---")

    mode = st.sidebar.radio(
        "Application Mode:",
        ["CBOM Manifest Audit", "Direct Codebase Scanner", "Migration Progress Delta", "Policy & NIST Catalog Reference"],
    )

    st.sidebar.markdown("---")
    st.sidebar.subheader("Manifest Selection")

    sample_options = {
        "Custom Upload (Drag & Drop)": None,
        "Enterprise Banking Core (Legacy Sprawl)": "samples/enterprise_banking_cbom.json",
        "Cloud-Native PQC Service (Quantum-Safe)": "samples/cloud_microservice_pqc_cbom.json",
        "Hybrid IPsec Gateway (Transition Ready)": "samples/hybrid_vpn_gateway_cbom.json",
        "Shadow IT Web Application (High Vulnerability)": "samples/shadow_it_sprawl_cbom.json",
        "Incomplete Third-Party SDK (Audit Gaps)": "samples/incomplete_metadata_cbom.json",
    }

    selected_sample = st.sidebar.selectbox("Load Sample CBOM:", list(sample_options.keys()))

    target_json_data = None
    manifest_display_name = "manifest.json"

    if selected_sample == "Custom Upload (Drag & Drop)":
        uploaded_file = st.sidebar.file_uploader("Upload CycloneDX 1.6 CBOM (.json):", type=["json"])
        if uploaded_file is not None:
            try:
                target_json_data = json.load(uploaded_file)
                manifest_display_name = uploaded_file.name
            except Exception as e:
                st.sidebar.error(f"Malformed JSON: {e}")
    else:
        sample_path = PROJECT_ROOT / sample_options[selected_sample]
        if sample_path.exists():
            with open(sample_path, "r", encoding="utf-8") as f:
                target_json_data = json.load(f)
            manifest_display_name = sample_path.name

    st.sidebar.markdown("---")
    st.sidebar.info(
        "**NIST Standards Baseline:**\n"
        "- FIPS 203: ML-KEM (Kyber)\n"
        "- FIPS 204: ML-DSA (Dilithium)\n"
        "- FIPS 205: SLH-DSA (SPHINCS+)\n"
        "- ECMA-424 / CycloneDX 1.6"
    )

    # Main Application Header
    st.markdown("<h1 class='main-title'>QuantumPulse</h1>", unsafe_allow_html=True)
    st.markdown("**Cryptographic Bill of Materials (CBOM) Analyzer & NIST Post-Quantum Cryptography Migration Platform**")
    st.markdown("---")

    if mode == "CBOM Manifest Audit":
        if target_json_data is None:
            st.warning("👈 Please select a sample CBOM from the sidebar or upload your own CycloneDX 1.6 JSON manifest to begin.")
            return

        # Run Analysis
        with st.spinner("Analyzing Cryptographic Assets & Policy Baselines..."):
            compliance_report, raw_assets = analyzer.parser.parse_data(target_json_data, manifest_name=manifest_display_name)
            evaluated_assets = analyzer.policy_engine.evaluate_assets(raw_assets)
            qri_summary, scored_assets = analyzer.risk_calculator.calculate_qri(evaluated_assets)
            directives = analyzer.nist_advisor.generate_advisories(scored_assets)

            report = AnalysisReport(
                timestamp=datetime.now(timezone.utc).isoformat(),
                manifest_name=manifest_display_name,
                standard_compliance=compliance_report,
                qri_summary=qri_summary,
                assets=scored_assets,
                directives=directives,
            )

        # Executive Metrics Row
        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            st.metric("Quantum Risk Index", f"{qri_summary.overall_score} / 100", delta=qri_summary.risk_level, delta_color="inverse")
        with col2:
            st.metric("Total Crypto Assets", qri_summary.total_crypto_assets)
        with col3:
            st.metric("Shor-Vulnerable Keys", qri_summary.classical_vulnerable_count, delta="CRQC Exposure", delta_color="inverse")
        with col4:
            st.metric("Broken Primitives", qri_summary.broken_count, delta="Immediate Fix", delta_color="inverse")
        with col5:
            st.metric("CycloneDX Adherence", f"{compliance_report.adherence_score}%", delta=f"Spec {compliance_report.spec_version}")

        st.markdown("###")

        # Tabbed Dashboard Sections
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 Executive Overview & Risk",
            "🔍 Cryptographic Inventory",
            "🛡️ NIST PQC Migration Advisor",
            "📋 CycloneDX ECMA-424 Audit",
            "📥 Reports & Exports",
        ])

        with tab1:
            row1_col1, row1_col2 = st.columns([1, 1])
            with row1_col1:
                st.plotly_chart(render_qri_gauge(qri_summary.overall_score, qri_summary.risk_level), use_container_width=True)
            with row1_col2:
                # Family Distribution Chart
                family_counts = {}
                for a in scored_assets:
                    fam_name = a.family.value
                    family_counts[fam_name] = family_counts.get(fam_name, 0) + 1
                
                df_fam = pd.DataFrame(list(family_counts.items()), columns=["Family", "Count"])
                fig_pie = px.pie(
                    df_fam,
                    names="Family",
                    values="Count",
                    title="<b>Cryptographic Taxonomy Distribution</b>",
                    hole=0.4,
                    color_discrete_sequence=px.colors.qualitative.Prism,
                )
                fig_pie.update_layout(height=280, margin=dict(l=20, r=20, t=40, b=10))
                st.plotly_chart(fig_pie, use_container_width=True)

            # Secondary Overview Cards
            c_a, c_b, c_c = st.columns(3)
            with c_a:
                st.info(f"**Harvest-Now-Decrypt-Later (HNDL) Threat:**\n\nAdversary interception exposure rating: **{qri_summary.hndl_exposure_index}/100** based on key exchange and data shelf-life longevity.")
            with c_b:
                st.warning(f"**Analysis Confidence:**\n\nRating: **{qri_summary.confidence_score}%**. {qri_summary.audit_gaps_count} audit gaps recorded due to missing manifest metadata.")
            with c_c:
                st.success(f"**Post-Quantum Readiness:**\n\nCompliant / Hybrid assets: **{qri_summary.safe_count + qri_summary.hybrid_count} / {qri_summary.total_crypto_assets}**.")

        with tab2:
            st.markdown("#### Discovered Cryptographic Primitives in Manifest")
            if scored_assets:
                data_records = []
                for a in scored_assets:
                    data_records.append({
                        "ID": a.id,
                        "Algorithm": a.name,
                        "Family": a.family.value,
                        "Key Size": a.key_size if a.key_size else "N/A",
                        "Curve / Mode": a.curve or a.mode or "-",
                        "Component / Context": f"{a.component_name} ({a.context_purpose or 'unspecified'})",
                        "Status": a.compliance_status.value.replace("_", " "),
                        "Asset QRI": a.individual_qri,
                        "OWASP A02 Category": a.owasp_category,
                    })
                df_assets = pd.DataFrame(data_records)

                # Search and Filter
                status_filter = st.multiselect("Filter by Compliance Status:", df_assets["Status"].unique(), default=df_assets["Status"].unique())
                filtered_df = df_assets[df_assets["Status"].isin(status_filter)]
                st.dataframe(filtered_df, use_container_width=True, hide_index=True)
            else:
                st.info("No cryptographic assets discovered in this manifest.")

        with tab3:
            st.markdown("#### NIST PQC Migration Directives & Engineering Roadmaps")
            if directives:
                st.caption("Targeting NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA).")
                
                # Performance Trade-offs Bar Chart
                st.markdown("##### 📈 Cryptographic Overhead Trade-Offs (Public Key & Ciphertext/Signature Expansion)")
                tradeoff_data = [
                    {"Primitive": "RSA-2048", "Category": "Classical Legacy", "Public Key (Bytes)": 256, "Payload/Sig (Bytes)": 256},
                    {"Primitive": "ECDSA-P256", "Category": "Classical Legacy", "Public Key (Bytes)": 64, "Payload/Sig (Bytes)": 64},
                    {"Primitive": "ML-KEM-768", "Category": "NIST FIPS 203 (PQC)", "Public Key (Bytes)": 1184, "Payload/Sig (Bytes)": 1088},
                    {"Primitive": "ML-DSA-65", "Category": "NIST FIPS 204 (PQC)", "Public Key (Bytes)": 1952, "Payload/Sig (Bytes)": 3309},
                    {"Primitive": "SLH-DSA-128s", "Category": "NIST FIPS 205 (Hash)", "Public Key (Bytes)": 32, "Payload/Sig (Bytes)": 7856},
                ]
                df_trade = pd.DataFrame(tradeoff_data)
                fig_trade = px.bar(
                    df_trade,
                    x="Primitive",
                    y=["Public Key (Bytes)", "Payload/Sig (Bytes)"],
                    barmode="group",
                    title="Key Size & Transmission Size Expansion Comparison",
                    color_discrete_sequence=["#3B82F6", "#10B981"],
                )
                fig_trade.update_layout(height=320, margin=dict(l=20, r=20, t=40, b=10))
                st.plotly_chart(fig_trade, use_container_width=True)

                # Directives Table
                dir_rows = []
                for d in directives:
                    dir_rows.append({
                        "Asset": d.asset_id,
                        "Current Algorithm": d.current_algorithm,
                        "NIST Replacement": d.recommended_replacement,
                        "Standard": d.nist_standard,
                        "Hybrid Option": d.hybrid_alternative or "-",
                        "Priority Tier": d.priority_tier,
                        "Deprecation Deadline": d.deprecation_deadline,
                        "Overhead": d.public_key_overhead or d.ciphertext_overhead or "-",
                    })
                st.dataframe(pd.DataFrame(dir_rows), use_container_width=True, hide_index=True)

                st.markdown("##### Actionable Engineering Directives:")
                for d in directives:
                    with st.expander(f"📌 {d.asset_id}: {d.current_algorithm} ➔ {d.recommended_replacement} ({d.priority_tier})"):
                        st.markdown(f"**Target Standard:** {d.nist_standard}")
                        if d.hybrid_alternative:
                            st.markdown(f"**Hybrid Migration Path:** `{d.hybrid_alternative}`")
                        st.markdown(f"**Overhead / Trade-Off:** {d.public_key_overhead} | {d.ciphertext_overhead}")
                        st.markdown(f"**Action Directive:** {d.action_plan}")

                        # Automated Migration Code Patch
                        patch = CodePatcher.get_patch_snippet(d.current_algorithm, d.recommended_replacement, language="python")
                        st.markdown("---")
                        st.markdown("###### 🛠️ Drop-in Implementation Code Patch:")
                        st.caption(patch["explanation"])
                        st.code(patch["code"], language="python")
            else:
                st.success("🎉 All discovered cryptographic primitives are already compliant with NIST PQC baselines. No remediation required!")

        with tab4:
            st.markdown("#### CycloneDX Standard (ECMA-424) Validation & Taxonomy Audit")
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f"- **Format:** `{compliance_report.bom_format}`")
                st.markdown(f"- **Specification Version:** `{compliance_report.spec_version}`")
                st.markdown(f"- **Schema Validation Status:** {'✅ Valid' if compliance_report.is_valid else '❌ Violations Detected'}")
                st.markdown(f"- **Standards Adherence Rating:** **{compliance_report.adherence_score} / 100**")
            with c2:
                st.markdown("**Taxonomy Coverage Breakdown:**")
                for k, v in compliance_report.taxonomy_coverage.items():
                    st.markdown(f"- `{k}`: **{v}** components")

            if compliance_report.schema_errors:
                st.error("Schema Validation Exceptions Detected:")
                for err in compliance_report.schema_errors:
                    st.code(err)

            if compliance_report.summary_notes:
                st.info("Standards Audit Recommendations:")
                for note in compliance_report.summary_notes:
                    st.markdown(f"• {note}")

        with tab5:
            st.markdown("#### Download Governance & Security Audit Reports")
            st.caption("Generate executive-ready audit documents and CI/CD interchange payloads.")

            # Generate dynamic PDF in-memory / tempfile
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_pdf:
                tmp_pdf_path = Path(tmp_pdf.name)
            
            Reporter.to_pdf(report, tmp_pdf_path)
            with open(tmp_pdf_path, "rb") as f:
                pdf_bytes = f.read()

            d_col1, d_col2, d_col3, d_col4 = st.columns(4)
            with d_col1:
                st.download_button(
                    label="📄 Download Executive PDF",
                    data=pdf_bytes,
                    file_name=f"{Path(manifest_display_name).stem}_quantumpulse_audit.pdf",
                    mime="application/pdf",
                )
            with d_col2:
                sarif_str = json.dumps(Reporter.to_sarif(report), indent=2)
                st.download_button(
                    label="🛡️ Download SARIF (CI/CD)",
                    data=sarif_str,
                    file_name=f"{Path(manifest_display_name).stem}.sarif",
                    mime="application/json",
                )
            with d_col3:
                json_str = Reporter.to_json(report)
                st.download_button(
                    label="📦 Download JSON Audit",
                    data=json_str,
                    file_name=f"{Path(manifest_display_name).stem}_quantumpulse.json",
                    mime="application/json",
                )
            with d_col4:
                md_str = Reporter.to_markdown(report)
                st.download_button(
                    label="📝 Download Markdown",
                    data=md_str,
                    file_name=f"{Path(manifest_display_name).stem}_summary.md",
                    mime="text/markdown",
                )

    elif mode == "Direct Codebase Scanner":
        st.markdown("### 🔍 Direct Codebase-to-CBOM Scanner")
        st.caption("Scan application source code directories (Python, Java, JS/TS, Go, X.509 certs) to automatically extract cryptographic primitives and synthesize a CycloneDX 1.6 CBOM.")

        col_dir, col_name = st.columns([3, 1])
        with col_dir:
            target_directory = st.text_input("Enter Project or Source Directory Path:", value="core")
        with col_name:
            app_label = st.text_input("Application Name:", value="QuantumPulse-System")

        if st.button("🚀 Scan Codebase & Synthesize CBOM", type="primary"):
            scan_path = Path(target_directory)
            if not scan_path.exists():
                st.error(f"Directory '{target_directory}' does not exist.")
            else:
                with st.spinner(f"Scanning '{target_directory}' for cryptographic implementations..."):
                    gen = CodebaseCBOMGenerator()
                    scanned_cbom = gen.scan_directory(scan_path, app_name=app_label)
                    st.success(f"Discovered {len(scanned_cbom.get('components', []))} components! CycloneDX 1.6 CBOM generated successfully.")

                    # Run instant audit on the generated CBOM
                    compliance_rep, raw_assets = analyzer.parser.parse_data(scanned_cbom, manifest_name=f"{app_label}.json")
                    eval_assets = analyzer.policy_engine.evaluate_assets(raw_assets)
                    qri_res, scored_assets = analyzer.risk_calculator.calculate_qri(eval_assets)
                    pqc_dirs = analyzer.nist_advisor.generate_advisories(scored_assets)

                    c1, c2, c3, c4 = st.columns(4)
                    with c1:
                        st.metric("Quantum Risk Index", f"{qri_res.overall_score} / 100", delta=qri_res.risk_level, delta_color="inverse")
                    with c2:
                        st.metric("Total Cryptographic Assets", qri_res.total_crypto_assets)
                    with c3:
                        st.metric("Shor-Vulnerable Assets", qri_res.classical_vulnerable_count, delta="CRQC Exposure", delta_color="inverse")
                    with c4:
                        st.metric("Broken Primitives", qri_res.broken_count, delta="Immediate Fix", delta_color="inverse")

                    st.markdown("---")
                    st.markdown("#### Discovered Assets Inventory:")
                    df_scanned = pd.DataFrame([{
                        "ID": a.id,
                        "Algorithm": a.name,
                        "Family": a.family.value,
                        "Key Size": a.key_size or "-",
                        "Purpose": a.context_purpose or "-",
                        "Status": a.compliance_status.value.replace("_", " "),
                        "Asset QRI": a.individual_qri,
                    } for a in scored_assets])
                    st.dataframe(df_scanned, use_container_width=True, hide_index=True)

                    # Download Generated CBOM JSON
                    st.download_button(
                        label="📦 Download Synthesized CycloneDX 1.6 CBOM JSON",
                        data=json.dumps(scanned_cbom, indent=2),
                        file_name=f"{app_label}_cbom.json",
                        mime="application/json",
                    )

    elif mode == "Migration Progress Delta":
        st.markdown("### Post-Quantum Migration Delta & Progress Tracking")
        st.caption("Quantify risk reduction by comparing a baseline CBOM with a post-remediation CBOM.")

        col_b, col_t = st.columns(2)
        with col_b:
            baseline_sel = st.selectbox(
                "Baseline CBOM (Pre-Migration):",
                ["samples/enterprise_banking_cbom.json", "samples/shadow_it_sprawl_cbom.json"],
            )
        with col_t:
            target_sel = st.selectbox(
                "Target CBOM (Post-Remediation):",
                ["samples/cloud_microservice_pqc_cbom.json", "samples/hybrid_vpn_gateway_cbom.json"],
            )

        if st.button("Run Migration Delta Analysis", type="primary"):
            comparer = CBOMComparer()
            delta = comparer.compare_files(PROJECT_ROOT / baseline_sel, PROJECT_ROOT / target_sel)

            st.success(delta.summary)

            c1, c2, c3, c4 = st.columns(4)
            with c1:
                st.metric("Baseline QRI", delta.baseline_qri)
            with c2:
                st.metric("Target QRI", delta.target_qri, delta=f"{delta.qri_delta:+0.1f}", delta_color="inverse")
            with c3:
                st.metric("Risk Reduction", f"{delta.risk_reduction_percent}%")
            with c4:
                st.metric("Remediated Algorithms", delta.remediated_count)

            # Resolved vs Remaining
            col_res, col_rem = st.columns(2)
            with col_res:
                st.markdown("##### ✅ Successfully Remediated / Replaced Primitives:")
                for r in delta.resolved_vulnerabilities:
                    st.markdown(f"- `{r}`")
            with col_rem:
                st.markdown("##### ⚠️ Remaining Primitives Requiring Action:")
                st.markdown(f"- Total vulnerable items remaining: **{delta.remaining_count}**")

    elif mode == "Policy & NIST Catalog Reference":
        st.markdown("### Cryptographic Policy & NIST Parameter Registry")
        rules = analyzer.policy_engine.algorithms_rules
        df_rules = pd.DataFrame(rules)
        st.dataframe(df_rules[["id", "name", "family", "classification", "shor_susceptible", "grover_susceptible", "deprecation_deadline"]], use_container_width=True)


if __name__ == "__main__":
    main()

