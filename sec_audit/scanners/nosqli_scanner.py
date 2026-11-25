"""
NoSQL Injection & MongoDB Operator Injection Auditor
Inspired by Strix NoSQL Injection playbook.
Audits source code for unsanitized document database queries, $where JavaScript execution, and unvalidated operator ingestion.
"""

import os
import re
import requests
from typing import List, Dict, Any, Optional
from ..models import Finding, Severity, Category
from ..config import SAST_EXTENSIONS, DEFAULT_TIMEOUT, DEFAULT_USER_AGENT
from ..ignore_matcher import IgnoreMatcher


class NoSQLIScanner:
    """
    Scans source code for NoSQL Injection vulnerabilities in MongoDB, Mongoose, and PyMongo.
    """

    PATTERNS = [
        # 1. Direct unvalidated request payload passed to collection query
        {
            "id": "NOSQLI-RAW-BODY-QUERY",
            "name": "NoSQL Injection via Raw Request Payload Ingestion",
            "severity": Severity.CRITICAL,
            "cvss": 9.4,
            "regex": re.compile(
                r"""(?i)(?:\.(?:find|findOne|findOneAndUpdate|countDocuments|deleteMany)\s*\(\s*(?:req\.body|req\.query|request\.(?:POST|data|json))\s*\))"""
            ),
            "description": "Entire request body or query object passed directly to NoSQL database query without schema whitelisting or sanitization. Attackers can inject MongoDB operators ($ne, $gt, $regex) to bypass authentication or dump database contents.",
            "remediation": "Do not pass req.body directly to queries. Explicitly cast fields (e.g. { username: String(req.body.username) }) or use mongo-sanitize.",
            "cwe": "CWE-943",
            "owasp": "A05:2025-Injection",
        },
        # 2. Insecure $where operator with dynamic string concatenation
        {
            "id": "NOSQLI-WHERE-CLAUSE",
            "name": "Dangerous MongoDB $where JavaScript Evaluation",
            "severity": Severity.CRITICAL,
            "cvss": 9.8,
            "regex": re.compile(
                r"""(?i)["']?\$where["']?\s*:\s*(?:f['"]|['"].*\+|\buser_input\b|req\.)"""
            ),
            "description": "MongoDB $where clause constructed with dynamic string interpolation. Attackers can execute arbitrary JavaScript on the database server, leading to Server-Side JavaScript Injection (SSJS) or Denial of Service.",
            "remediation": "Avoid $where clauses entirely. Use standard declarative MongoDB query expressions ($eq, $expr) instead of dynamic JavaScript strings.",
            "cwe": "CWE-943",
            "owasp": "A05:2025-Injection",
        },
        # 3. Dynamic regex injection in NoSQL query
        {
            "id": "NOSQLI-REGEX-INJECTION",
            "name": "Unsanitized Regex Injection in NoSQL Query (ReDoS / Data Leakage)",
            "severity": Severity.HIGH,
            "cvss": 7.5,
            "regex": re.compile(
                r"""(?i)["']\$regex["']\s*:\s*(?:req\.|params|user_input|data)"""
            ),
            "description": "User input passed directly into MongoDB $regex query operator without escaping special regex characters. Attackers can craft catastrophic backtracking expressions (ReDoS) or enumerate sensitive data character-by-character.",
            "remediation": "Escape user input using lodash.escapeRegExp before passing to $regex, or use exact string matching with $eq.",
            "cwe": "CWE-943",
            "owasp": "A05:2025-Injection",
        },
    ]

    def __init__(
        self,
        target_dir: Optional[str] = None,
        target_url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.target_dir = os.path.abspath(target_dir) if target_dir else None
        self.target_url = target_url
        self.timeout = timeout
        self.matcher = IgnoreMatcher(self.target_dir) if self.target_dir else None

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        if self.target_dir and os.path.exists(self.target_dir):
            findings.extend(self._scan_source())
        return findings

    def _scan_source(self) -> List[Finding]:
        findings = []
        for root, dirs, files in os.walk(self.target_dir):
            if self.matcher:
                dirs[:] = [
                    d for d in dirs
                    if not self.matcher.is_ignored(os.path.join(root, d), is_dir=True) and not d.startswith(".")
                ]

            for file in files:
                fpath = os.path.join(root, file)
                if self.matcher and self.matcher.is_ignored(fpath, is_dir=False):
                    continue

                ext = os.path.splitext(file)[1].lower()
                if ext not in SAST_EXTENSIONS:
                    continue

                relpath = os.path.relpath(fpath, self.target_dir)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except Exception:
                    continue

                for idx, line in enumerate(lines, start=1):
                    stripped = line.strip()
                    if stripped.startswith(("#", "//", "/*", "*")):
                        continue

                    # Check for sanitization guard in preceding 5 lines (Counterevidence)
                    start_idx = max(0, idx - 6)
                    preceding = "".join(lines[start_idx:idx]).lower()
                    if "mongo-sanitize" in preceding or "sanitize(" in preceding:
                        continue

                    for rule in self.PATTERNS:
                        if rule["regex"].search(line):
                            findings.append(
                                Finding(
                                    title=rule["name"],
                                    category=Category.NOSQLI.value,
                                    severity=rule["severity"],
                                    cvss_score=rule["cvss"],
                                    description=rule["description"],
                                    evidence=f"{relpath}:{idx}\n> {stripped[:150]}",
                                    remediation=rule["remediation"],
                                    location=f"{relpath}:{idx}",
                                    cwe_id=rule.get("cwe"),
                                    owasp_category=rule.get("owasp"),
                                    closure_state="CONFIRMED",
                                )
                            )
        return findings
