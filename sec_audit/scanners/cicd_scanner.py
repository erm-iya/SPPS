"""
CI/CD Pipeline Security Auditor for GitHub Actions and GitLab CI
Audits workflow manifests for PwnRequest, script injection, unpinned actions, and secret exposure.
"""

import os
import re
from typing import List, Dict, Any, Optional
from ..models import Finding, Severity, Category
from ..ignore_matcher import IgnoreMatcher

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class CICDScanner:
    """
    Scans CI/CD pipeline definitions (.github/workflows/*.yml, .gitlab-ci.yml)
    for supply chain and execution security vulnerabilities.
    """

    UNTRUSTED_CONTEXT_PATTERNS = [
        r"\$\{\{\s*github\.event\.issue\.title\s*\}\}",
        r"\$\{\{\s*github\.event\.issue\.body\s*\}\}",
        r"\$\{\{\s*github\.event\.comment\.body\s*\}\}",
        r"\$\{\{\s*github\.event\.pull_request\.title\s*\}\}",
        r"\$\{\{\s*github\.event\.pull_request\.body\s*\}\}",
        r"\$\{\{\s*github\.head_ref\s*\}\}",
    ]

    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir)
        self.matcher = IgnoreMatcher(self.target_dir)
        self.workflow_files_count: int = 0

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        if not os.path.exists(self.target_dir):
            return findings

        # Check GitHub Actions workflows
        workflows_dir = os.path.join(self.target_dir, ".github", "workflows")
        if os.path.isdir(workflows_dir):
            for file in os.listdir(workflows_dir):
                if file.lower().endswith((".yml", ".yaml")):
                    fpath = os.path.join(workflows_dir, file)
                    relpath = os.path.relpath(fpath, self.target_dir)
                    self.workflow_files_count += 1
                    findings.extend(self._audit_github_workflow(fpath, relpath))

        # Check GitLab CI manifest
        gitlab_ci = os.path.join(self.target_dir, ".gitlab-ci.yml")
        if os.path.isfile(gitlab_ci):
            relpath = os.path.relpath(gitlab_ci, self.target_dir)
            self.workflow_files_count += 1
            findings.extend(self._audit_gitlab_ci(gitlab_ci, relpath))

        return findings

    def _audit_github_workflow(self, fpath: str, relpath: str) -> List[Finding]:
        findings = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            return findings

        # 1. PwnRequest: pull_request_target with head branch checkout
        has_pr_target = bool(re.search(r"""\bpull_request_target\b""", content))
        if has_pr_target:
            checkout_untrusted = bool(
                re.search(r"""actions\/checkout@""", content)
                and re.search(r"""ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}""", content)
            )
            if checkout_untrusted:
                findings.append(
                    Finding(
                        title="Critical PwnRequest Vulnerability (pull_request_target checkout)",
                        category=Category.CICD.value,
                        severity=Severity.CRITICAL,
                        cvss_score=9.5,
                        description=(
                            "Workflow triggers on 'pull_request_target' with elevated repository permissions "
                            "and checks out the untrusted pull request code. Attackers can execute arbitrary "
                            "malicious code in the context of the base repository and exfiltrate secrets."
                        ),
                        evidence=f"File: {relpath}\nTrigger: pull_request_target\nAction: actions/checkout with pull_request.head ref",
                        remediation="Do not checkout untrusted PR code in pull_request_target workflows. Use standard 'pull_request' trigger with read-only tokens.",
                        location=f"{relpath}:1",
                        cwe_id="CWE-829",
                        owasp_category="A03:2025-Software Supply Chain Failures",
                    )
                )

        # 2. Line-by-line inspection for Script Injections, Unpinned Actions, and Secrets in CLI
        in_run_block = False
        run_start_idx = 0

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            # Track run: blocks
            if re.match(r"""^\s*run:\s*(?:\||>|$)""", line):
                in_run_block = True
                run_start_idx = idx

            # Script injection check
            for pattern in self.UNTRUSTED_CONTEXT_PATTERNS:
                if re.search(pattern, line):
                    # Flag if inside run step or on same run line
                    if in_run_block or "run:" in line:
                        findings.append(
                            Finding(
                                title="CI/CD Script Injection via Untrusted GitHub Context",
                                category=Category.CICD.value,
                                severity=Severity.HIGH,
                                cvss_score=8.5,
                                description=(
                                    "Untrusted GitHub context expression is interpolated directly into a shell execution script. "
                                    "Attackers can inject shell metacharacters in issue/PR titles or comments to achieve Command Injection in the runner."
                                ),
                                evidence=f"{relpath}:{idx}\n> {stripped}",
                                remediation="Pass untrusted GitHub contexts into environment variables (env:) and reference them as shell variables ($TITLE).",
                                location=f"{relpath}:{idx}",
                                cwe_id="CWE-78",
                                owasp_category="A05:2025-Injection",
                            )
                        )
                        break

            # Unpinned Action check (uses: actions/checkout@v1, @main, @master)
            m_uses = re.search(r"""uses:\s*([a-zA-Z0-9_\-\.\/]+)@([a-zA-Z0-9_\-\.]+)""", line)
            if m_uses:
                action_name = m_uses.group(1)
                tag = m_uses.group(2)
                # If tag is not a 40-character commit SHA
                if not re.match(r"^[0-9a-fA-F]{40}$", tag):
                    if tag.lower() in ("main", "master", "latest") or re.match(r"^v[0-9]+(\.[0-9]+)*$", tag):
                        findings.append(
                            Finding(
                                title=f"CI/CD Unpinned Action ({action_name}@{tag})",
                                category=Category.CICD.value,
                                severity=Severity.LOW,
                                cvss_score=3.5,
                                description=(
                                    f"Action '{action_name}' is pinned to mutable tag/branch '@{tag}' instead of an immutable commit SHA. "
                                    "If the upstream action author or repository is compromised, malicious code will be automatically ingested into your build runner."
                                ),
                                evidence=f"{relpath}:{idx}\n> {stripped}",
                                remediation=f"Pin '{action_name}' to a full 40-character commit SHA hash.",
                                location=f"{relpath}:{idx}",
                                cwe_id="CWE-829",
                                owasp_category="A03:2025-Software Supply Chain Failures",
                            )
                        )

            # Plaintext secret passed in CLI arguments
            if re.search(r"""run:.*--(?:token|secret|password|key)\s*=?\s*\$\{\{\s*secrets\.""", line):
                findings.append(
                    Finding(
                        title="Plaintext Secret Exposed in CLI Command Arguments",
                        category=Category.CICD.value,
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        description="Secret interpolated directly into command-line arguments, exposing it in process tables and execution traces.",
                        evidence=f"{relpath}:{idx}\n> {stripped}",
                        remediation="Map the secret to an environment variable in 'env:' and reference it via environment variable instead of CLI argument.",
                        location=f"{relpath}:{idx}",
                        cwe_id="CWE-532",
                        owasp_category="A04:2025-Cryptographic Failures",
                    )
                )

        return findings

    def _audit_gitlab_ci(self, fpath: str, relpath: str) -> List[Finding]:
        findings = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            return findings

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Plaintext secret exposure in gitlab script
            if re.search(r"""\$\{[A-Z0-9_]*(?:PASSWORD|SECRET|KEY|TOKEN)[A-Z0-9_]*\}""", line) and any(
                cmd in line for cmd in ("curl", "wget", "--password", "--token")
            ):
                findings.append(
                    Finding(
                        title="GitLab CI Secret Exposure in Script Arguments",
                        category=Category.CICD.value,
                        severity=Severity.MEDIUM,
                        cvss_score=5.5,
                        description="Sensitive variable passed directly into command-line arguments in GitLab CI job.",
                        evidence=f"{relpath}:{idx}\n> {stripped}",
                        remediation="Ensure masked variables are used and passed via secure environment bindings.",
                        location=f"{relpath}:{idx}",
                        cwe_id="CWE-532",
                        owasp_category="A04:2025-Cryptographic Failures",
                    )
                )
        return findings
