"""
QuantumPulse Multi-Format Reporting Engine
Generates audit-ready reports in JSON, SARIF (for GitHub/GitLab CI/CD gates),
Markdown, and executive PDF reports powered by ReportLab.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from core.models import AnalysisReport, ComplianceStatus, RemediationDirective


class Reporter:
    @staticmethod
    def to_json(report: AnalysisReport, indent: int = 2) -> str:
        """Exports full report as formatted JSON string."""
        return json.dumps(report.model_dump(), indent=indent, default=str)

    @staticmethod
    def to_sarif(report: AnalysisReport) -> Dict[str, Any]:
        """
        Exports findings in SARIF v2.1.0 format for native integration
        with GitHub Code Scanning and GitLab Security Dashboards.
        """
        rules = [
            {
                "id": "QP-SHOR-001",
                "name": "ShorQuantumVulnerability",
                "shortDescription": {"text": "Asymmetric primitive vulnerable to Shor's algorithm on CRQC."},
                "defaultConfiguration": {"level": "error"},
                "helpUri": "https://csrc.nist.gov/projects/post-quantum-cryptography",
                "properties": {"tags": ["security", "cryptography", "OWASP-A02:2021", "PQC"]},
            },
            {
                "id": "QP-BROKEN-002",
                "name": "ClassicallyBrokenPrimitive",
                "shortDescription": {"text": "Cryptographic primitive broken under classical computing baselines."},
                "defaultConfiguration": {"level": "error"},
                "helpUri": "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final",
                "properties": {"tags": ["security", "cryptography", "OWASP-A02:2021", "Deprecated"]},
            },
            {
                "id": "QP-GROVER-003",
                "name": "GroverSymmetricDegradation",
                "shortDescription": {"text": "Symmetric key length halved by Grover's quantum search."},
                "defaultConfiguration": {"level": "warning"},
                "properties": {"tags": ["cryptography", "PQC"]},
            },
            {
                "id": "QP-AUDIT-004",
                "name": "CBOMAuditGap",
                "shortDescription": {"text": "Cryptographic Bill of Materials lacks required specification parameters."},
                "defaultConfiguration": {"level": "note"},
                "properties": {"tags": ["compliance", "CBOM", "ECMA-424"]},
            },
        ]

        results = []
        for asset in report.assets:
            if asset.compliance_status == ComplianceStatus.BROKEN_INSECURE:
                rule_id = "QP-BROKEN-002"
                level = "error"
            elif asset.shor_susceptible:
                rule_id = "QP-SHOR-001"
                level = "error"
            elif asset.grover_susceptible:
                rule_id = "QP-GROVER-003"
                level = "warning"
            else:
                continue

            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"Cryptographic asset '{asset.name}' in '{asset.component_name}' violates post-quantum policy: {asset.reason or 'Vulnerable primitive'}. Recommended replacement: {asset.remediation.get('recommended_replacement') if asset.remediation else 'Upgrade'}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": report.manifest_name},
                            "region": {"snippet": {"text": f"bom-ref: {asset.bom_ref}"}},
                        }
                    }
                ],
            })

        for asset in report.assets:
            for gap in asset.audit_gaps:
                results.append({
                    "ruleId": "QP-AUDIT-004",
                    "level": "note",
                    "message": {"text": f"Audit Gap in '{asset.name}': {gap.description}"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": report.manifest_name}}}],
                })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "QuantumPulse",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/QuantumPulse/QuantumPulse",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

    @staticmethod
    def to_markdown(report: AnalysisReport) -> str:
        """Generates clean GitHub Flavored Markdown executive summary."""
        qri = report.qri_summary
        comp = report.standard_compliance

        status_badge = {
            "SAFE": "🟢 SAFE",
            "LOW": "🔵 LOW",
            "MEDIUM": "🟡 MEDIUM",
            "HIGH": "🟠 HIGH",
            "CRITICAL": "🔴 CRITICAL",
        }.get(qri.risk_level, qri.risk_level)

        lines = [
            f"# QuantumPulse Security & PQC Migration Advisory",
            f"**Manifest:** `{report.manifest_name}` | **Scan Timestamp:** `{report.timestamp}`",
            "",
            "## Executive Risk & Compliance Summary",
            f"- **Quantum Risk Index (QRI):** **{qri.overall_score} / 100** ({status_badge})",
            f"- **Analysis Confidence:** **{qri.confidence_score}%** (Estimated Audit Gaps: {qri.audit_gaps_count})",
            f"- **CycloneDX ECMA-424 Compliance:** **{comp.adherence_score}%** (Spec Version: {comp.spec_version})",
            f"- **HNDL Exposure Index:** **{qri.hndl_exposure_index} / 100**",
            "",
            "| Asset Metric | Count |",
            "| :--- | :--- |",
            f"| Total Cryptographic Assets | **{qri.total_crypto_assets}** |",
            f"| Quantum-Safe / Compliant | **{qri.safe_count}** |",
            f"| Shor-Vulnerable (Classical Asymmetric) | **{qri.classical_vulnerable_count}** |",
            f"| Classically Broken / Deprecated | **{qri.broken_count}** |",
            f"| Hybrid Transition Active | **{qri.hybrid_count}** |",
            "",
            "---",
            "",
            "## Discovered Cryptographic Inventory",
            "| ID | Algorithm | Family | Key Size | Context/Purpose | Status | Individual QRI |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for a in report.assets:
            status_text = a.compliance_status.value.replace("_", " ")
            lines.append(
                f"| `{a.id}` | **{a.name}** | {a.family.value} | {a.key_size or 'N/A'} | {a.context_purpose or 'Unspecified'} | {status_text} | **{a.individual_qri}** |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## NIST Post-Quantum Cryptography Migration Directives",
            "| Asset | Current Primitive | NIST Replacement | Standard | Priority Tier | Deadline | Overhead / Trade-off |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ])

        for d in report.directives:
            overhead = d.public_key_overhead or d.ciphertext_overhead or "Low"
            lines.append(
                f"| `{d.asset_id}` | `{d.current_algorithm}` | **{d.recommended_replacement}** | {d.nist_standard} | **{d.priority_tier}** | {d.deprecation_deadline} | {overhead} |"
            )

        lines.extend([
            "",
            "### Detailed Engineering Directives:",
            "",
        ])

        for d in report.directives:
            lines.append(f"#### `{d.asset_id}`: {d.current_algorithm} -> {d.recommended_replacement} ({d.priority_tier})")
            lines.append(f"- **Target Standard:** {d.nist_standard}")
            if d.hybrid_alternative:
                lines.append(f"- **Hybrid Transition Path:** `{d.hybrid_alternative}`")
            lines.append(f"- **Action Plan:** {d.action_plan}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def to_pdf(report: AnalysisReport, output_path: str | Path) -> Path:
        """Generates a professional, audit-ready executive PDF report using ReportLab."""
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            str(out_p),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "TitleStyle",
            parent=styles["Heading1"],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor("#1E293B"),
            spaceAfter=6,
        )
        subtitle_style = ParagraphStyle(
            "SubTitleStyle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748B"),
            spaceAfter=15,
        )
        section_style = ParagraphStyle(
            "SectionStyle",
            parent=styles["Heading2"],
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#0F172A"),
            spaceBefore=12,
            spaceAfter=8,
        )
        body_style = ParagraphStyle(
            "BodyStyle",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#334155"),
        )
        table_hdr_style = ParagraphStyle(
            "TableHdr",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            fontName="Helvetica-Bold",
            textColor=colors.white,
        )

        story = []

        # 1. Header Banner
        story.append(Paragraph("QuantumPulse: Cryptographic & PQC Audit Report", title_style))
        story.append(
            Paragraph(
                f"Generated: {report.timestamp} | Manifest: <b>{report.manifest_name}</b> | Standard: CycloneDX 1.6 (ECMA-424)",
                subtitle_style,
            )
        )

        # 2. Executive KPI Summary Table
        qri = report.qri_summary
        comp = report.standard_compliance

        risk_color = {
            "SAFE": colors.HexColor("#10B981"),
            "LOW": colors.HexColor("#06B6D4"),
            "MEDIUM": colors.HexColor("#F59E0B"),
            "HIGH": colors.HexColor("#F97316"),
            "CRITICAL": colors.HexColor("#EF4444"),
        }.get(qri.risk_level, colors.HexColor("#64748B"))

        kpi_data = [
            [
                Paragraph("<b>QUANTUM RISK INDEX (QRI)</b>", body_style),
                Paragraph("<b>RISK LEVEL</b>", body_style),
                Paragraph("<b>TOTAL ASSETS</b>", body_style),
                Paragraph("<b>SHOR VULNERABLE</b>", body_style),
                Paragraph("<b>BROKEN CIPHERS</b>", body_style),
                Paragraph("<b>STANDARDS ADHERENCE</b>", body_style),
            ],
            [
                Paragraph(f"<font size=14><b>{qri.overall_score} / 100</b></font>", body_style),
                Paragraph(f"<font size=12 color='{risk_color.hexval()}'><b>{qri.risk_level}</b></font>", body_style),
                Paragraph(f"<font size=12><b>{qri.total_crypto_assets}</b></font>", body_style),
                Paragraph(f"<font size=12 color='#DC2626'><b>{qri.classical_vulnerable_count}</b></font>", body_style),
                Paragraph(f"<font size=12 color='#B91C1C'><b>{qri.broken_count}</b></font>", body_style),
                Paragraph(f"<font size=12 color='#059669'><b>{comp.adherence_score}%</b></font>", body_style),
            ],
        ]

        kpi_table = Table(kpi_data, colWidths=[90, 85, 80, 95, 90, 100])
        kpi_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ])
        )
        story.append(kpi_table)
        story.append(Spacer(1, 14))

        # 3. Discovered Assets Inventory
        story.append(Paragraph("1. Cryptographic Inventory & Exposure Breakdown", section_style))
        inv_data = [[
            Paragraph("ID", table_hdr_style),
            Paragraph("Algorithm", table_hdr_style),
            Paragraph("Family", table_hdr_style),
            Paragraph("Key Size", table_hdr_style),
            Paragraph("Purpose / Context", table_hdr_style),
            Paragraph("Status", table_hdr_style),
            Paragraph("Asset QRI", table_hdr_style),
        ]]

        for a in report.assets[:15]:  # limit for clean single-page formatting
            inv_data.append([
                Paragraph(f"<b>{a.id}</b>", body_style),
                Paragraph(f"<b>{a.name}</b>", body_style),
                Paragraph(a.family.value, body_style),
                Paragraph(str(a.key_size or "N/A"), body_style),
                Paragraph(a.context_purpose or "Unspecified", body_style),
                Paragraph(a.compliance_status.value.replace("_", " "), body_style),
                Paragraph(f"<b>{a.individual_qri}</b>", body_style),
            ])

        inv_table = Table(inv_data, colWidths=[40, 75, 90, 45, 110, 130, 50])
        inv_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F1F5F9")]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(inv_table)
        story.append(Spacer(1, 14))

        # 4. NIST PQC Migration Directives
        story.append(Paragraph("2. NIST Post-Quantum Cryptography Migration Directives", section_style))
        pqc_data = [[
            Paragraph("Asset", table_hdr_style),
            Paragraph("Current Primitive", table_hdr_style),
            Paragraph("NIST Replacement", table_hdr_style),
            Paragraph("Standard", table_hdr_style),
            Paragraph("Priority Tier", table_hdr_style),
            Paragraph("Deadline", table_hdr_style),
        ]]

        for d in report.directives[:10]:
            pqc_data.append([
                Paragraph(f"<b>{d.asset_id}</b>", body_style),
                Paragraph(d.current_algorithm, body_style),
                Paragraph(f"<b>{d.recommended_replacement}</b>", body_style),
                Paragraph(d.nist_standard, body_style),
                Paragraph(f"<b>{d.priority_tier}</b>", body_style),
                Paragraph(d.deprecation_deadline, body_style),
            ])

        pqc_table = Table(pqc_data, colWidths=[45, 95, 100, 120, 95, 85])
        pqc_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#047857")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#ECFDF5")]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(pqc_table)

        doc.build(story)
        return out_p

