"""
XML External Entity (XXE) Injection Auditor
Inspired by Strix XXE vulnerability playbook.
Audits source code for unsafe XML parser configurations, external entity resolution, and missing entity expansion guards.
"""

import os
import re
from typing import List, Dict, Any, Optional
from ..models import Finding, Severity, Category
from ..config import SAST_EXTENSIONS
from ..ignore_matcher import IgnoreMatcher


class XXEScanner:
    """
    Scans source code across multiple languages for XML External Entity (XXE) parsing risks.
    """

    PATTERNS = [
        # 1. Python lxml without resolve_entities=False
        {
            "id": "XXE-PYTHON-LXML",
            "name": "Unsafe XML Parsing with External Entity Resolution (Python lxml)",
            "severity": Severity.HIGH,
            "cvss": 8.6,
            "regex": re.compile(
                r"""(?i)(?:(?:lxml\.)?etree\.(?:parse|fromstring|XMLParser)|XMLParser)\s*\([^)]*resolve_entities\s*=\s*True|XMLParser\s*\([^)]*no_network\s*=\s*False"""
            ),
            "description": "XML parser configured to resolve external entities or allow network resolution. Attackers can supply malicious DOCTYPE definitions to exfiltrate local files (/etc/passwd, secrets) or trigger Server-Side Request Forgery (SSRF).",
            "remediation": "Use defusedxml (e.g. defusedxml.lxml.parse) or set resolve_entities=False and no_network=True on parser instances.",
            "cwe": "CWE-611",
            "owasp": "A05:2025-Injection",
        },
        # 2. PHP libxml with entity loader enabled
        {
            "id": "XXE-PHP-LIBXML",
            "name": "XML External Entity Processing Enabled in PHP",
            "severity": Severity.CRITICAL,
            "cvss": 9.1,
            "regex": re.compile(
                r"""libxml_disable_entity_loader\s*\(\s*false\s*\)"""
            ),
            "description": "PHP libxml entity loader explicitly enabled (false). Disabling entity protections exposes all subsequent simplexml_load_string, DOMDocument, and XMLReader operations to XXE exploits.",
            "remediation": "Do not call libxml_disable_entity_loader(false). Keep entity loading disabled and pass LIBXML_NONET | LIBXML_NOENT to parser functions.",
            "cwe": "CWE-611",
            "owasp": "A05:2025-Injection",
        },
        # 3. Node.js libxmljs with noent: true (Entity expansion)
        {
            "id": "XXE-NODE-NOENT",
            "name": "Unsafe XML Entity Substitution in Node.js (libxmljs noent)",
            "severity": Severity.HIGH,
            "cvss": 8.2,
            "regex": re.compile(
                r"""(?:parseXml(?:String)?\s*\([^)]*noent\s*:\s*true|dtdload\s*:\s*true)"""
            ),
            "description": "Node.js XML parser configured with 'noent: true' or 'dtdload: true', causing external DTD entities to be fetched and substituted during parsing.",
            "remediation": "Ensure 'noent' is set to false (default) and disable external DTD loading ('dtdload: false').",
            "cwe": "CWE-611",
            "owasp": "A05:2025-Injection",
        },
        # 4. XML payload containing SYSTEM / PUBLIC external entity declaration
        {
            "id": "XXE-PAYLOAD-DECLARATION",
            "name": "Embedded XML External Entity Declaration (DOCTYPE SYSTEM)",
            "severity": Severity.CRITICAL,
            "cvss": 9.5,
            "regex": re.compile(
                r"""<!ENTITY\s+[a-zA-Z0-9_\-]+\s+SYSTEM\s+["'](?:file|http|https|ftp|gopher|expect):\/\/"""
            ),
            "description": "Direct XML external entity declaration discovered in template or test fixture, exposing local file paths or remote protocols.",
            "remediation": "Remove external DOCTYPE entity references and enforce disallow-doctype-decl on XML parsers.",
            "cwe": "CWE-611",
            "owasp": "A05:2025-Injection",
        },
    ]

    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir)
        self.matcher = IgnoreMatcher(self.target_dir)

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        if not os.path.exists(self.target_dir):
            return findings

        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [
                d for d in dirs
                if not self.matcher.is_ignored(os.path.join(root, d), is_dir=True) and not d.startswith(".")
            ]

            for file in files:
                fpath = os.path.join(root, file)
                if self.matcher and self.matcher.is_ignored(fpath, is_dir=False):
                    continue

                ext = os.path.splitext(file)[1].lower()
                # Include XML, XSL, and code extensions
                if ext not in SAST_EXTENSIONS and ext not in (".xml", ".xsl", ".xsd"):
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

                    # Skip rule definitions and metadata strings in security audit tools
                    if stripped.startswith(('"regex":', "'regex':", '"name":', "'name':", '"description":', "'description':", '"remediation":', "'remediation':")):
                        continue
                    if re.search(r'''(?:description|remediation|title|message|help|doc)\s*[:=]\s*['"]''', line):
                        continue

                    # Check for defusedxml or secure parser imports (Counterevidence)
                    if "defusedxml" in line:
                        continue

                    for rule in self.PATTERNS:
                        if rule["regex"].search(line):
                            findings.append(
                                Finding(
                                    title=rule["name"],
                                    category=Category.XXE.value,
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
