"""
Detailed Markdown Security Audit Reporter
Generates structured Markdown reports with OWASP Top 10:2025 mapping and reproducible PoC curls.
"""

import os
from typing import Optional
from ..models import ScanResult, Severity


class MarkdownReporter:
    """
    Renders structured Markdown reports for ticketing (GitHub/GitLab issues, Jira) and technical audits.
    """

    SEVERITY_BADGES = {
        Severity.CRITICAL.value: "🔴 CRITICAL",
        Severity.HIGH.value: "🟠 HIGH",
        Severity.MEDIUM.value: "🟡 MEDIUM",
        Severity.LOW.value: "🔵 LOW",
        Severity.INFO.value: "⚪ INFO",
    }

    def __init__(self, result: ScanResult):
        self.result = result
        self.result.calculate_score()

    def export(self, filepath: str) -> None:
        md = self.generate()
        target_path = os.path.abspath(filepath)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(md)

    def generate(self) -> str:
        r = self.result
        lines = []

        # 1. Header
        lines.append("# 🔒 SecAudit Enterprise Security Audit Report")
        lines.append("")
        lines.append(f"- **Scan Date:** `{r.scan_date}`")
        if r.target_url:
            lines.append(f"- **Target URL:** `{r.target_url}`")
        if r.target_dir:
            lines.append(f"- **Source Directory:** `{r.target_dir}`")
        lines.append(f"- **Audit Duration:** `{r.duration_seconds:.2f} seconds`")
        lines.append(f"- **Overall Security Score:** **{r.security_score}/100** (Grade: **{r.grade}**)")
        lines.append("")

        # 2. Executive Summary Tables
        lines.append("## 📊 Executive Summary")
        lines.append("")

        # Volume & Scale Inventory
        vm = r.volume_metrics
        lines.append("### Project Scale & Volume Inventory")
        lines.append("| Metric | Value |")
        lines.append("| :--- | :---: |")
        lines.append(f"| 📏 Lines of Code (LoC) | `{vm.total_loc:,}` |")
        lines.append(f"| 📁 Scanned Files | `{vm.total_files:,}` |")
        lines.append(f"| 📦 Third-Party Dependencies | `{vm.total_dependencies}` |")
        lines.append(f"| 🌐 Endpoints & Probes Audited | `{vm.total_endpoints}` |")
        lines.append("")

        # Sub-Pillar Scores
        ps = r.pillar_scores
        lines.append("### Security Domain Sub-Pillars")
        lines.append("| Security Pillar | Health Score | Status |")
        lines.append("| :--- | :---: | :---: |")
        lines.append(f"| 💻 Source Code & Secrets (SAST) | **{ps.sast_score}%** | {'✅ Healthy' if ps.sast_score >= 80 else '⚠️ Needs Attention'} |")
        lines.append(f"| 📦 Supply Chain & Dependencies (SCA) | **{ps.sca_score}%** | {'✅ Healthy' if ps.sca_score >= 80 else '⚠️ Needs Attention'} |")
        lines.append(f"| 🐳 Infrastructure & Container (IaC) | **{ps.iac_score}%** | {'✅ Healthy' if ps.iac_score >= 80 else '⚠️ Needs Attention'} |")
        lines.append(f"| 🌐 Attack Surface & Network (DAST/API) | **{ps.dast_score}%** | {'✅ Healthy' if ps.dast_score >= 80 else '⚠️ Needs Attention'} |")
        lines.append("")

        lines.append("### Findings by Severity")
        lines.append("| Severity | Count |")
        lines.append("| :--- | :---: |")
        for sev in [Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value, Severity.LOW.value, Severity.INFO.value]:
            cnt = r.stats.get(sev, 0)
            badge = self.SEVERITY_BADGES.get(sev, sev)
            lines.append(f"| {badge} | {cnt} |")
        lines.append("")

        if r.owasp_summary:
            lines.append("### OWASP Top 10:2025 Compliance Alignment")
            lines.append("| OWASP Category | Finding Count |")
            lines.append("| :--- | :---: |")
            for cat, count in sorted(r.owasp_summary.items()):
                lines.append(f"| **{cat}** | {count} |")
            lines.append("")

        if r.detected_tech:
            lines.append("### Detected Technologies & Stack")
            tech_items = [f"`{t['name']}` ({t.get('category', 'General')})" for t in r.detected_tech]
            lines.append(", ".join(tech_items))
            lines.append("")

        # 3. Detailed Findings
        lines.append("## 🔍 Detailed Vulnerability Findings")
        lines.append("")

        if not r.findings:
            lines.append("> ✅ **Clean Codebase / Target:** No security misconfigurations or vulnerabilities were identified.")
            return "\n".join(lines)

        for idx, f in enumerate(r.findings, start=1):
            badge = self.SEVERITY_BADGES.get(f.severity.value, f.severity.value)
            lines.append(f"### {idx}. [{badge}] {f.title}")
            lines.append("")
            lines.append(f"- **Category:** `{f.category}`")
            lines.append(f"- **Status (Closure Discipline):** `{f.closure_state}`")
            if f.counterevidence:
                lines.append(f"- **Counterevidence / Context:** `{f.counterevidence}`")
            if f.owasp_category:
                lines.append(f"- **OWASP Top 10:2025:** `{f.owasp_category}`")
            if f.cwe_id:
                lines.append(f"- **CWE ID:** `{f.cwe_id}`")
            if f.cvss_score:
                lines.append(f"- **CVSS v3.1 Score:** `{f.cvss_score}`")
            if f.location:
                lines.append(f"- **Location:** `{f.location}`")
            lines.append("")
            lines.append(f"**Description:**  \n{f.description}")
            lines.append("")

            if f.evidence:
                lines.append("**Evidence / Output:**")
                lines.append("```text")
                lines.append(f.evidence)
                lines.append("```")
                lines.append("")

            if f.poc_curl:
                lines.append("**Proof of Concept (PoC Request):**")
                lines.append("```bash")
                lines.append(f.poc_curl)
                lines.append("```")
                lines.append("")

            lines.append(f"**💡 Remediation:**  \n{f.remediation}")
            lines.append("")

            if f.fix_snippet:
                lines.append("**Ready-to-copy Configuration Snippets:**")
                for stype, scode in f.fix_snippet.items():
                    lines.append(f"<details><summary>{stype.upper()}</summary>\n\n```{stype}\n{scode}\n```\n</details>")
                lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)
