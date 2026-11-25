"""
Server-Side Template Injection (SSTI) Auditor
Inspired by Strix SSTI vulnerability playbook.
Audits source code for dynamic template compilation and evaluates live endpoints for template evaluation probes.
"""

import os
import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Optional
from ..models import Finding, Severity, Category
from ..config import SAST_EXTENSIONS, DEFAULT_TIMEOUT, DEFAULT_USER_AGENT
from ..ignore_matcher import IgnoreMatcher


class SSTIScanner:
    """
    Scans source code and live web targets for Server-Side Template Injection (SSTI) flaws.
    """

    SAST_PATTERNS = [
        # 1. Python Jinja2 / Mako dynamic template string compilation
        {
            "id": "SSTI-JINJA-DYNAMIC",
            "name": "Server-Side Template Injection in Jinja2 / Flask",
            "severity": Severity.CRITICAL,
            "cvss": 9.8,
            "regex": re.compile(
                r"""(?i)(?:render_template_string|jinja2\.Template|Environment\([^)]*\)\.from_string)\s*\(\s*(?:f['"].*\{|req\.|params|request\.(?:args|form|values)|user_input|data)"""
            ),
            "description": "User input concatenated directly into a Jinja2 template string before rendering. Attackers can evaluate arbitrary Python expressions and achieve Remote Code Execution (RCE).",
            "remediation": "Do not pass user input to render_template_string(). Pass user input as template context variables: render_template('page.html', var=user_input).",
            "cwe": "CWE-1336",
            "owasp": "A05:2025-Injection",
        },
        # 2. Node.js EJS / Pug / Handlebars dynamic template compilation
        {
            "id": "SSTI-NODE-DYNAMIC",
            "name": "Server-Side Template Injection in Node.js Template Engine",
            "severity": Severity.CRITICAL,
            "cvss": 9.8,
            "regex": re.compile(
                r"""(?i)(?:ejs\.render|pug\.compile|pug\.render|Handlebars\.compile|nunjucks\.renderString)\s*\(\s*(?:`[^`]*\$\{|req\.(?:query|body|params)|user_input)"""
            ),
            "description": "User input interpolated into Node.js template string prior to compilation. Attackers can escape the sandbox to execute host process commands via prototype pollution or child_process.",
            "remediation": "Compile templates from static files only, and pass dynamic parameters solely via template context data.",
            "cwe": "CWE-1336",
            "owasp": "A05:2025-Injection",
        },
        # 3. Java Velocity / Freemarker / Thymeleaf SpEL evaluation
        {
            "id": "SSTI-JAVA-DYNAMIC",
            "name": "Server-Side Template Injection in Java Engine (Velocity / SpEL / Freemarker)",
            "severity": Severity.CRITICAL,
            "cvss": 9.8,
            "regex": re.compile(
                r"""(?i)(?:Velocity\.evaluate|VelocityEngine\.evaluate|TemplateModelException|ExpressionParser\.parseExpression)\s*\([^)]*(?:request\.getParameter|req\.getParameter|userInput)"""
            ),
            "description": "Dynamic evaluation of untrusted template expressions in Java applications. Allows Java reflection and ProcessBuilder execution.",
            "remediation": "Disable dynamic expression compilation and enforce strict sandboxing with safe evaluation contexts.",
            "cwe": "CWE-1336",
            "owasp": "A05:2025-Injection",
        },
        # 4. RCE Gadget chains inside templates
        {
            "id": "SSTI-GADGET-CHAIN",
            "name": "SSTI Remote Code Execution Gadget Chain in Template Source",
            "severity": Severity.CRITICAL,
            "cvss": 9.8,
            "regex": re.compile(
                r"""(?i)(?:__mro__|__subclasses__|lipsum\.__globals__|cycler\.__globals__|Runtime\.getRuntime\(\)|ProcessBuilder)"""
            ),
            "description": "Known SSTI sandbox escape gadget chain detected in template or source code, indicating exploit payloads or insecure reflection.",
            "remediation": "Remove dangerous reflection gadgets and ensure templates run in restricted sandboxes without global namespace exposure.",
            "cwe": "CWE-1336",
            "owasp": "A05:2025-Injection",
        },
    ]

    DIFFERENTIAL_PROBES = [
        {"probe": "{{7*7}}", "expected": "49", "engine": "Jinja2 / Twig / Nunjucks"},
        {"probe": "${7*7}", "expected": "49", "engine": "Velocity / Freemarker / SpEL"},
        {"probe": "<%= 7*7 %>", "expected": "49", "engine": "EJS / ERB"},
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
        if self.target_url:
            findings.extend(self._probe_live_url())
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

                    # Skip rule definitions and metadata strings in security audit tools
                    if stripped.startswith(('"regex":', "'regex':", '"name":', "'name':", '"description":', "'description':", '"remediation":', "'remediation':", 'r"""', "r'''", 'r"', "r'")):
                        continue
                    if re.search(r'''(?:description|remediation|title|message|help|doc)\s*[:=]\s*['"]''', line):
                        continue

                    # Suppress static string renders (counterevidence)
                    if "render_template_string" in line and (
                        ('"""' in line and line.count('"""') == 2 and "{" not in line) or
                        ("'" in line and "{" not in line and "f'" not in line)
                    ):
                        continue

                    for rule in self.SAST_PATTERNS:
                        if rule["regex"].search(line):
                            findings.append(
                                Finding(
                                    title=rule["name"],
                                    category=Category.SSTI.value,
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

    def _probe_live_url(self) -> List[Finding]:
        findings = []
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        if not params:
            return findings

        headers = {"User-Agent": DEFAULT_USER_AGENT}
        for param_name in params.keys():
            for probe_info in self.DIFFERENTIAL_PROBES:
                probe_val = probe_info["probe"]
                expected = probe_info["expected"]
                engine = probe_info["engine"]

                mutated_params = dict(params)
                mutated_params[param_name] = [probe_val]
                new_query = urlencode(mutated_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                try:
                    resp = requests.get(test_url, headers=headers, timeout=self.timeout, verify=False)  # nosec: defensive auditor scanning target endpoints
                    # If expected math result (e.g. 49) is reflected and the raw probe is NOT reflected verbatim
                    if expected in resp.text and probe_val not in resp.text:
                        findings.append(
                            Finding(
                                title=f"Active Server-Side Template Injection Detected ({engine})",
                                category=Category.SSTI.value,
                                severity=Severity.CRITICAL,
                                cvss_score=9.8,
                                description=(
                                    f"Differential mathematical probe '{probe_val}' evaluated to '{expected}' "
                                    f"when injected into query parameter '{param_name}'. Target executes expressions in {engine}."
                                ),
                                evidence=f"URL: {test_url}\nProbe: {probe_val} -> Evaluated Response Body: {expected}",
                                remediation="Do not concatenate user-supplied input into template strings. Enforce context variable binding.",
                                location=test_url,
                                cwe_id="CWE-1336",
                                owasp_category="A05:2025-Injection",
                                poc_curl=f'curl -s "{test_url}"',
                                closure_state="CONFIRMED",
                            )
                        )
                        break
                except Exception:
                    continue

        return findings
