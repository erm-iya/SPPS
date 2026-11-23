"""
API Specification & Endpoint Security Scanner (OpenAPI / Swagger Auditor)
Inspired by Strix's autonomous API security auditing capabilities.
"""

import os
import json
import re
import requests
from urllib.parse import urljoin
from typing import List, Dict, Any, Optional
from ..models import Finding, Severity, Category
from ..config import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT
from ..ignore_matcher import IgnoreMatcher

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class APISpecScanner:
    """
    Discovers, parses, and audits OpenAPI / Swagger specifications for API authorization flaws,
    unauthenticated administrative endpoints, query string credential leakage, and unbounded resource consumption.
    """

    KNOWN_SPEC_PATHS = [
        "swagger.json",
        "swagger.yaml",
        "swagger.yml",
        "openapi.json",
        "openapi.yaml",
        "openapi.yml",
        "v2/api-docs",
        "v3/api-docs",
        "api-docs",
    ]

    SENSITIVE_PARAM_NAMES = {
        "password", "pass", "pwd", "token", "secret", "api_key", "apikey",
        "auth", "access_token", "private_key", "jwt"
    }

    def __init__(
        self,
        target_dir: Optional[str] = None,
        target_url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.target_dir = os.path.abspath(target_dir) if target_dir else None
        self.target_url = target_url
        self.timeout = timeout
        self.headers = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/json"}
        self.matcher = IgnoreMatcher(self.target_dir) if self.target_dir else None
        self.total_routes_count: int = 0

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Local Filesystem Discovery
        if self.target_dir and os.path.exists(self.target_dir):
            for root, dirs, files in os.walk(self.target_dir):
                if self.matcher:
                    dirs[:] = [d for d in dirs if not self.matcher.is_ignored(os.path.join(root, d), is_dir=True)]

                for file in files:
                    file_lower = file.lower()
                    if file_lower in self.KNOWN_SPEC_PATHS or "openapi" in file_lower or "swagger" in file_lower:
                        fpath = os.path.join(root, file)
                        if self.matcher and self.matcher.is_ignored(fpath, is_dir=False):
                            continue
                        relpath = os.path.relpath(fpath, self.target_dir)
                        spec = self._load_local_spec(fpath)
                        if spec:
                            findings.extend(self._audit_spec(spec, location_prefix=relpath))

        # 2. Remote URL Probing
        if self.target_url:
            base_url = self.target_url.rstrip("/") + "/"
            for probe_path in self.KNOWN_SPEC_PATHS:
                test_url = urljoin(base_url, probe_path)
                spec = self._probe_remote_spec(test_url)
                if spec:
                    findings.append(
                        Finding(
                            title=f"Publicly Exposed OpenAPI / Swagger Specification ({probe_path})",
                            category=Category.API.value,
                            severity=Severity.LOW,
                            cvss_score=3.5,
                            description=f"Publicly accessible API documentation discovered at {test_url}. Attackers can map backend endpoints, schemas, and parameter requirements.",
                            evidence=f"HTTP 200 OK -> {test_url}",
                            remediation="Restrict access to OpenAPI / Swagger UI endpoints in production environments.",
                            location=test_url,
                            cwe_id="CWE-200",
                            reference="https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                            poc_curl=f'curl -s "{test_url}"',
                            owasp_category="A02:2025-Security Misconfiguration",
                        )
                    )
                    findings.extend(self._audit_spec(spec, location_prefix=test_url))
                    break

        return findings

    def _load_local_spec(self, spec_path: str) -> Optional[Dict[str, Any]]:
        try:
            with open(spec_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if spec_path.endswith((".json",)):
                return json.loads(content)
            elif YAML_AVAILABLE and spec_path.endswith((".yaml", ".yml")):
                return yaml.safe_load(content)
            else:
                return json.loads(content)
        except Exception:
            return None

    def _probe_remote_spec(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            resp = requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False,  # nosec: defensive auditor inspecting target endpoints
                allow_redirects=False,
            )
            if resp.status_code == 200:
                ct = resp.headers.get("Content-Type", "").lower()
                if "json" in ct or resp.text.strip().startswith("{"):
                    data = resp.json()
                    if isinstance(data, dict) and ("swagger" in data or "openapi" in data or "paths" in data):
                        return data
        except Exception:
            pass
        return None

    def _audit_spec(self, spec: Dict[str, Any], location_prefix: str) -> List[Finding]:
        findings: List[Finding] = []
        paths = spec.get("paths", {})
        if not isinstance(paths, dict):
            return findings

        self.total_routes_count += len(paths)

        global_security = spec.get("security", [])

        for route, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            for method, details in methods.items():
                if method.lower() not in ["get", "post", "put", "delete", "patch", "options", "head"]:
                    continue
                if not isinstance(details, dict):
                    continue

                operation_id = details.get("operationId") or f"{method.upper()} {route}"
                sec_requirements = details.get("security", global_security)

                # 1. Unauthenticated Admin / Internal Endpoints (OWASP API5:2023 - Broken Function Level Authorization)
                is_admin_path = any(kw in route.lower() for kw in ["/admin", "/internal", "/system", "/manage", "/config"])
                if is_admin_path and not sec_requirements:
                    findings.append(
                        Finding(
                            title=f"API Route Missing Authentication Requirement ({method.upper()} {route})",
                            category=Category.API.value,
                            severity=Severity.HIGH,
                            cvss_score=8.1,
                            description=f"Administrative/internal endpoint '{route}' ({method.upper()}) declares no security requirements in the API specification.",
                            evidence=f"Endpoint: {method.upper()} {route}\nSecurity: None defined",
                            remediation="Enforce authentication and role-based authorization (RBAC) on administrative API routes.",
                            location=f"{location_prefix} -> {route}",
                            cwe_id="CWE-306",
                            reference="https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                            poc_curl=f'curl -I -s -X {method.upper()} "https://target-domain{route}"',
                            owasp_category="A01:2025-Broken Access Control & SSRF",
                        )
                    )

                # 2. Sensitive Parameters Passed via Query Strings (OWASP A04:2025 / API2)
                params = details.get("parameters", [])
                if isinstance(params, list):
                    for p in params:
                        if isinstance(p, dict) and p.get("in") == "query":
                            pname = str(p.get("name", "")).lower()
                            if pname in self.SENSITIVE_PARAM_NAMES or any(s in pname for s in ["password", "secret", "token"]):
                                findings.append(
                                    Finding(
                                        title=f"Sensitive Credential Transmitted via Query String ({p.get('name')})",
                                        category=Category.API.value,
                                        severity=Severity.MEDIUM,
                                        cvss_score=5.5,
                                        description=f"Endpoint '{method.upper()} {route}' accepts sensitive credential '{p.get('name')}' as a URL query parameter. Query parameters are logged in server access logs, browser history, and proxy servers.",
                                        evidence=f"Route: {route}\nParam: ?{p.get('name')}=",
                                        remediation="Transmit sensitive tokens, keys, and passwords via Authorization headers or secure JSON POST request bodies.",
                                        location=f"{location_prefix} -> {route} (?{p.get('name')})",
                                        cwe_id="CWE-598",
                                        reference="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
                                        poc_curl=f'curl -s -X {method.upper()} "https://target-domain{route}?{p.get("name")}=secret"',
                                        owasp_category="A04:2025-Cryptographic Failures",
                                    )
                                )

                # 3. Unbounded List Collection Endpoints (OWASP API4:2023 - Unrestricted Resource Consumption)
                if method.lower() == "get" and route.endswith(("s", "list", "all", "search")) and not route.endswith(("/{id}", "/{name}", "/{uid}")):
                    param_names = [p.get("name", "").lower() for p in params if isinstance(p, dict)]
                    has_pagination = any(kw in param_names for kw in ["limit", "page", "offset", "size", "per_page", "cursor"])
                    if not has_pagination and len(params) <= 2:
                        findings.append(
                            Finding(
                                title=f"API Collection Endpoint Lacks Pagination Controls ({route})",
                                category=Category.API.value,
                                severity=Severity.LOW,
                                cvss_score=3.7,
                                description=f"List endpoint '{method.upper()} {route}' does not define pagination parameters (e.g. limit/offset/page), risking unrestricted resource consumption and Denial of Service (DoS).",
                                evidence=f"Endpoint: GET {route}\nDeclared params: {', '.join(param_names) or 'None'}",
                                remediation="Implement mandatory pagination limits (e.g. max 50 items per page) on all list endpoints.",
                                location=f"{location_prefix} -> {route}",
                                cwe_id="CWE-770",
                                reference="https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                                poc_curl=f'curl -s "https://target-domain{route}"',
                                owasp_category="A01:2025-Broken Access Control & SSRF",
                            )
                        )

        return findings
