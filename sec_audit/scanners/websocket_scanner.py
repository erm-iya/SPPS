"""
WebSocket Security Auditor (Transport Encryption & CSWSH Analysis)
Audits source code for cleartext ws:// transport and missing Origin validation during handshakes.
"""

import os
import re
from typing import List, Optional
from ..models import Finding, Severity, Category
from ..config import SAST_EXTENSIONS
from ..ignore_matcher import IgnoreMatcher


class WebSocketScanner:
    """
    Scans source code for unencrypted WebSocket transport and Cross-Site WebSocket Hijacking (CSWSH) flaws.
    """

    PATTERNS = [
        # 1. Cleartext WebSocket transport
        {
            "id": "WS-INSECURE-TRANSPORT",
            "name": "Unencrypted WebSocket Protocol Used (ws://)",
            "severity": Severity.MEDIUM,
            "cvss": 5.5,
            "regex": re.compile(r"""(?:new\s+WebSocket\s*\(\s*['"]ws:\/\/|io\s*\(\s*['"]ws:\/\/|connect\s*\(\s*['"]ws:\/\/)"""),
            "description": "Cleartext WebSocket connection (ws://) detected. Traffic is transmitted unencrypted across the network and can be intercepted or manipulated by on-path attackers.",
            "remediation": "Enforce TLS-encrypted WebSocket communication using 'wss://' scheme exclusively.",
            "cwe": "CWE-319",
            "owasp": "A04:2025-Cryptographic Failures",
        },
        # 2. Server without origin verification (CSWSH risk)
        {
            "id": "WS-MISSING-ORIGIN-CHECK",
            "name": "Missing Origin Validation in WebSocket Handshake (CSWSH)",
            "severity": Severity.HIGH,
            "cvss": 7.8,
            "regex": re.compile(
                r"""(?:new\s+WebSocket\.Server\s*\(\s*\{[^}]*verifyClient\s*:\s*(?:false|null)|cors\s*:\s*\{[^}]*origin\s*:\s*['"]\*['"]|origins\s*=\s*\[\s*['"]\*['"]\s*\])"""
            ),
            "description": "WebSocket server explicitly disables client verification or allows wildcard '*' origin. Browsers do not enforce Same-Origin Policy on WebSockets, allowing malicious sites to initiate Cross-Site WebSocket Hijacking (CSWSH) and steal data using victim cookies.",
            "remediation": "Implement strict Origin validation in the WebSocket handshake (verifyClient in Node.js ws, or allowed_origins in Socket.io / FastAPI).",
            "cwe": "CWE-346",
            "owasp": "A01:2025-Broken Access Control & SSRF",
        },
    ]

    def __init__(self, target_dir: Optional[str] = None):
        self.target_dir = os.path.abspath(target_dir) if target_dir else None
        self.matcher = IgnoreMatcher(self.target_dir) if self.target_dir else None
        self.scanned_files_count: int = 0

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        if not self.target_dir or not os.path.exists(self.target_dir):
            return findings

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

                self.scanned_files_count += 1
                relpath = os.path.relpath(fpath, self.target_dir)
                findings.extend(self._audit_file(fpath, relpath))

        return findings

    def _audit_file(self, fpath: str, relpath: str) -> List[Finding]:
        findings = []
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return findings

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*")):
                continue

            for pattern in self.PATTERNS:
                if pattern["regex"].search(line):
                    findings.append(
                        Finding(
                            title=pattern["name"],
                            category=Category.WEBSOCKET.value,
                            severity=pattern["severity"],
                            cvss_score=pattern["cvss"],
                            description=pattern["description"],
                            evidence=f"{relpath}:{idx}\n> {stripped[:150]}",
                            remediation=pattern["remediation"],
                            location=f"{relpath}:{idx}",
                            cwe_id=pattern.get("cwe"),
                            owasp_category=pattern["owasp"],
                        )
                    )

        return findings
