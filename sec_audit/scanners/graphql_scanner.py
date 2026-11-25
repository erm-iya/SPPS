"""
GraphQL Security & Schema Introspection Auditor
DAST endpoint probing and SAST schema audit inspired by Strix security testing.
"""

import os
import re
import requests
from urllib.parse import urljoin
from typing import List, Optional
from ..models import Finding, Severity, Category
from ..config import DEFAULT_TIMEOUT, DEFAULT_USER_AGENT
from ..ignore_matcher import IgnoreMatcher


class GraphQLScanner:
    """
    Audits GraphQL endpoints and schemas for introspection leakage,
    field suggestion disclosures, and missing query depth validation.
    """

    KNOWN_GRAPHQL_PATHS = [
        "graphql",
        "api/graphql",
        "v1/graphql",
        "v2/graphql",
        "query",
        "api/query",
    ]

    INTROSPECTION_QUERY = """
    query IntrospectionCheck {
        __schema {
            queryType { name }
            types { name kind }
        }
    }
    """

    SUGGESTION_PROBE = """
    query FieldSuggestionCheck {
        nonExistentSecurityProbeField12345
    }
    """

    def __init__(
        self,
        target_dir: Optional[str] = None,
        target_url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.target_dir = os.path.abspath(target_dir) if target_dir else None
        self.target_url = target_url
        self.timeout = timeout
        self.headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.matcher = IgnoreMatcher(self.target_dir) if self.target_dir else None
        self.schema_files_count: int = 0

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        # 1. DAST Probing on Live URL
        if self.target_url:
            findings.extend(self._probe_remote_graphql())

        # 2. SAST Local Schema & Resolver Audit
        if self.target_dir and os.path.exists(self.target_dir):
            findings.extend(self._audit_local_schemas())

        return findings

    def _probe_remote_graphql(self) -> List[Finding]:
        findings = []
        base_url = self.target_url.rstrip("/") + "/"

        for path in self.KNOWN_GRAPHQL_PATHS:
            endpoint_url = urljoin(base_url, path)
            try:
                # 1. Test Introspection
                resp = requests.post(
                    endpoint_url,
                    json={"query": self.INTROSPECTION_QUERY},
                    headers=self.headers,
                    timeout=self.timeout,
                    verify=False,  # nosec: defensive auditor scanning target endpoints
                )
                if resp.status_code == 200:
                    data = resp.json()
                    schema_data = data.get("data", {}).get("__schema")
                    if schema_data and "types" in schema_data:
                        types_count = len(schema_data.get("types", []))
                        findings.append(
                            Finding(
                                title=f"GraphQL Introspection Enabled in Production ({path})",
                                category=Category.GRAPHQL.value,
                                severity=Severity.MEDIUM,
                                cvss_score=5.3,
                                description=(
                                    f"GraphQL endpoint at {endpoint_url} has Introspection enabled, exposing {types_count} schema types, "
                                    "queries, mutations, and internal entity relationships to unauthenticated users."
                                ),
                                evidence=f"Endpoint: {endpoint_url}\nHTTP 200 OK -> data.__schema.types ({types_count} types)",
                                remediation="Disable GraphQL Introspection in production configurations (e.g. introspection: false in Apollo Server / Yoga).",
                                location=endpoint_url,
                                cwe_id="CWE-200",
                                reference="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                                poc_curl=f'curl -s -X POST "{endpoint_url}" -H "Content-Type: application/json" -d \'{{"query": "{{ __schema {{ queryType {{ name }} }} }}"}}\'',
                                owasp_category="A02:2025-Security Misconfiguration",
                            )
                        )

                        # 2. Test Field Suggestion Information Disclosure
                        resp_suggest = requests.post(
                            endpoint_url,
                            json={"query": self.SUGGESTION_PROBE},
                            headers=self.headers,
                            timeout=self.timeout,
                            verify=False,  # nosec
                        )
                        if "Did you mean" in resp_suggest.text or "suggest" in resp_suggest.text.lower():
                            findings.append(
                                Finding(
                                    title=f"GraphQL Field Suggestions Enabled ({path})",
                                    category=Category.GRAPHQL.value,
                                    severity=Severity.LOW,
                                    cvss_score=3.5,
                                    description=(
                                        f"The GraphQL server at {endpoint_url} returns 'Did you mean ...?' suggestions for invalid field queries, "
                                        "allowing attackers to brute-force and enumerate hidden internal schema fields even when introspection is disabled."
                                    ),
                                    evidence=f"Endpoint: {endpoint_url}\nServer response contains field suggestions.",
                                    remediation="Disable field suggestions in production (e.g. using graphql-disable-suggestions).",
                                    location=endpoint_url,
                                    cwe_id="CWE-209",
                                    reference="https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                                    poc_curl=f'curl -s -X POST "{endpoint_url}" -H "Content-Type: application/json" -d \'{{"query": "{{ nonExistentSecurityProbeField12345 }}"}}\'',
                                    owasp_category="A02:2025-Security Misconfiguration",
                                )
                            )
                        break  # Stop probing once active GraphQL endpoint is confirmed
            except Exception:
                continue

        return findings

    def _audit_local_schemas(self) -> List[Finding]:
        findings = []
        for root, dirs, files in os.walk(self.target_dir):
            if self.matcher:
                dirs[:] = [d for d in dirs if not self.matcher.is_ignored(os.path.join(root, d), is_dir=True)]

            for file in files:
                file_lower = file.lower()
                fpath = os.path.join(root, file)
                if self.matcher and self.matcher.is_ignored(fpath, is_dir=False):
                    continue

                relpath = os.path.relpath(fpath, self.target_dir)

                # Check GraphQL schema and configuration files
                if file_lower.endswith((".graphql", ".gql")) or "graphql" in file_lower:
                    self.schema_files_count += 1
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()

                        # Check for deeply nested recursive types without max depth limiter
                        if re.search(r"""type\s+(\w+)\s*\{[^}]*:\s*\[?\1\]?[^}]*\}""", content):
                            findings.append(
                                Finding(
                                    title="Recursive GraphQL Schema Definition (Query Depth Bomb Risk)",
                                    category=Category.GRAPHQL.value,
                                    severity=Severity.MEDIUM,
                                    cvss_score=5.5,
                                    description=(
                                        f"Recursive schema type relationship detected in {relpath}. Without query depth limiting middleware, "
                                        "clients can craft deeply nested cyclic queries causing server denial of service (DoS)."
                                    ),
                                    evidence=f"Schema File: {relpath}\nCyclic type reference discovered.",
                                    remediation="Enforce query depth limiting with graphql-depth-limit (e.g. maxDepth: 6).",
                                    location=relpath,
                                    cwe_id="CWE-400",
                                    owasp_category="A05:2025-Injection",
                                )
                            )
                    except Exception:
                        pass

        return findings
