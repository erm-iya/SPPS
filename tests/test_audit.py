"""
Comprehensive automated unit test suite for SecAudit 2.0 Enterprise
"""

import os
import json
import tempfile
import unittest
from sec_audit.models import ScanResult, Severity, Category, Finding
from sec_audit.ignore_matcher import IgnoreMatcher
from sec_audit.scanners.sast_scanner import SASTScanner
from sec_audit.scanners.iac_scanner import IaCScanner
from sec_audit.scanners.license_scanner import LicenseScanner
from sec_audit.scanners.csp_evaluator import CSPEvaluator
from sec_audit.scanners.dns_scanner import DNSScanner
from sec_audit.scanners.sca_scanner import SCAScanner
from sec_audit.remediation.fix_generator import FixGenerator
from sec_audit.reporting.json_reporter import JSONReporter
from sec_audit.reporting.html_reporter import HTMLReporter
from sec_audit.reporting.sarif_reporter import SARIFReporter
from sec_audit.reporting.markdown_reporter import MarkdownReporter
from sec_audit.scanners.api_spec_scanner import APISpecScanner


class TestSecAudit2(unittest.TestCase):

    def test_sast_scanner_secrets_and_injection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_code_path = os.path.join(tmpdir, "vulnerable.py")
            with open(sample_code_path, "w", encoding="utf-8") as f:
                f.write(
                    """
# OpenAI Key
openai_key = "sk-1234567890abcdef1234567890abcdef"

# Dangerous deserialization
import pickle
pickle.loads(b"data")
"""
                )

            # Test .env.production scanning
            env_path = os.path.join(tmpdir, ".env.production")
            with open(env_path, "w", encoding="utf-8") as f:
                f.write("DB_PASSWORD='supersecretproductionpassword123'\n")

            scanner = SASTScanner(tmpdir)
            findings = scanner.scan()

            self.assertTrue(len(findings) >= 2)
            titles = [f.title for f in findings]
            self.assertTrue(any("OpenAI" in t for t in titles))
            self.assertTrue(any("Deserialization" in t for t in titles))

    def test_iac_dockerfile_and_k8s_audit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Dockerfile
            dockerfile_path = os.path.join(tmpdir, "Dockerfile")
            with open(dockerfile_path, "w", encoding="utf-8") as f:
                f.write(
                    """FROM node:latest
ENV DB_PASSWORD=my_hardcoded_pass123
CMD ["npm", "start"]
"""
                )

            # 2. Kubernetes Deployment manifest
            k8s_path = os.path.join(tmpdir, "deployment.yaml")
            with open(k8s_path, "w", encoding="utf-8") as f:
                f.write(
                    """apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
spec:
  template:
    spec:
      containers:
      - name: web
        image: nginx:latest
        securityContext:
          privileged: true
          allowPrivilegeEscalation: true
        volumeMounts:
        - mountPath: /host-root
          name: host-vol
      volumes:
      - name: host-vol
        hostPath:
          path: /etc
"""
                )

            scanner = IaCScanner(tmpdir)
            findings = scanner.scan()

            self.assertTrue(len(findings) >= 4)
            titles = [f.title for f in findings]
            # Dockerfile checks
            self.assertTrue(any("Dockerfile" in t and "latest" in t.lower() for t in titles))
            # K8s checks
            self.assertTrue(any("Kubernetes" in t and "Privileged" in t for t in titles))
            self.assertTrue(any("Kubernetes" in t and "Host Path" in t for t in titles))

    def test_csp_evaluator_with_and_without_nonce(self):
        # 1. Weak CSP without nonce
        weak_csp = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *;"
        evaluator1 = CSPEvaluator(weak_csp, "https://example.com")
        findings1 = evaluator1.evaluate()

        self.assertTrue(len(findings1) >= 3)
        titles1 = [f.title for f in findings1]
        self.assertTrue(any("unsafe-inline" in t for t in titles1))
        self.assertTrue(any(f.severity == Severity.HIGH for f in findings1 if "unsafe-inline" in f.title))

        # 2. CSP with nonce fallback for legacy browsers
        modern_csp = "default-src 'self'; script-src 'self' 'nonce-R4nd0m123' 'unsafe-inline';"
        evaluator2 = CSPEvaluator(modern_csp, "https://example.com")
        findings2 = evaluator2.evaluate()

        inline_findings = [f for f in findings2 if "unsafe-inline" in f.title]
        self.assertTrue(len(inline_findings) >= 1)
        # Should be downgraded to LOW severity due to nonce protection
        self.assertEqual(inline_findings[0].severity, Severity.LOW)

    def test_fix_generator(self):
        nginx_fix = FixGenerator.get_header_fix("Strict-Transport-Security")
        self.assertIsNotNone(nginx_fix)
        self.assertIn("nginx", nginx_fix)
        self.assertIn("max-age=31536000", nginx_fix["nginx"])

    def test_sarif_export_windows_paths_and_rule_uniqueness(self):
        res = ScanResult(target_url="https://example.com")
        res.findings.extend([
            Finding(
                title="Missing HSTS",
                category="Headers",
                severity=Severity.HIGH,
                description="HSTS missing",
                remediation="Add header",
                cwe_id="CWE-319",
                location=r"D:\Projects\SPPS\index.js:42",
            ),
            Finding(
                title="Missing CSP",
                category="Headers",
                severity=Severity.HIGH,
                description="CSP missing",
                remediation="Add CSP",
                cwe_id="CWE-1021",
                location=r"D:\Projects\SPPS\server.js:88",
            ),
            Finding(
                title="Weak CSP unsafe-inline",
                category="CSP",
                severity=Severity.MEDIUM,
                description="Contains unsafe-inline",
                remediation="Remove unsafe-inline",
                cwe_id="CWE-1021",  # Same CWE ID but distinct finding
                location=r"D:\Projects\SPPS\server.js:90",
            ),
        ])
        res.calculate_score()

        with tempfile.TemporaryDirectory() as tmpdir:
            sarif_file = os.path.join(tmpdir, "results.sarif")
            SARIFReporter(res).export(sarif_file)

            self.assertTrue(os.path.exists(sarif_file))
            with open(sarif_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            runs = data.get("runs", [])
            self.assertEqual(len(runs), 1)
            rules = runs[0]["tool"]["driver"]["rules"]
            # Ensure both CWE-1021 findings generated distinct rules without colliding
            self.assertEqual(len(rules), 3)

            results = runs[0]["results"]
            self.assertEqual(len(results), 3)
            # Verify Windows drive letter was preserved and line number correctly parsed
            first_loc = results[0]["locations"][0]["physicalLocation"]
            self.assertIn("index.js", first_loc["artifactLocation"]["uri"])
            self.assertEqual(first_loc["region"]["startLine"], 42)

    def test_ignore_matcher_avoid_substring_overmatch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ignore_file = os.path.join(tmpdir, ".sppsignore")
            with open(ignore_file, "w", encoding="utf-8") as f:
                f.write("test\n# a comment\nbuild/\n")

            matcher = IgnoreMatcher(tmpdir)

            # Substrings that shouldn't be matched
            self.assertFalse(matcher.is_ignored(os.path.join(tmpdir, "latest_controller.py"), is_dir=False))
            self.assertFalse(matcher.is_ignored(os.path.join(tmpdir, "contest.html"), is_dir=False))
            self.assertFalse(matcher.is_ignored(os.path.join(tmpdir, "src", "feature_tester.ts"), is_dir=False))

            # Exact matches that should be ignored
            self.assertTrue(matcher.is_ignored(os.path.join(tmpdir, "test"), is_dir=True))
            self.assertTrue(matcher.is_ignored(os.path.join(tmpdir, "build"), is_dir=True))

    def test_dns_apex_domain_extraction(self):
        scanner1 = DNSScanner("https://sub.example.com/page")
        self.assertEqual(scanner1.apex_domain, "example.com")

        # Multi-part ccTLDs
        scanner2 = DNSScanner("https://api.service.co.uk")
        self.assertEqual(scanner2.apex_domain, "service.co.uk")

        scanner3 = DNSScanner("portal.university.ac.ir")
        self.assertEqual(scanner3.apex_domain, "university.ac.ir")

    def test_sca_dependency_parsers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # package.json
            pkg_json_path = os.path.join(tmpdir, "package.json")
            with open(pkg_json_path, "w", encoding="utf-8") as f:
                json.dump({
                    "dependencies": {
                        "express": "^4.18.2",
                        "lodash": "~4.17.21"
                    }
                }, f)

            # requirements.txt
            req_path = os.path.join(tmpdir, "requirements.txt")
            with open(req_path, "w", encoding="utf-8") as f:
                f.write("requests>=2.28.0\njinja2==3.1.2\n")

            scanner = SCAScanner(tmpdir, check_online=False)
            npm_pkgs = scanner._parse_package_json(pkg_json_path)
            self.assertEqual(len(npm_pkgs), 2)
            self.assertEqual(dict(npm_pkgs)["express"], "4.18.2")
            self.assertEqual(dict(npm_pkgs)["lodash"], "4.17.21")

            py_pkgs = scanner._parse_requirements_txt(req_path)
            self.assertEqual(len(py_pkgs), 2)
            self.assertEqual(dict(py_pkgs)["requests"], "2.28.0")
            self.assertEqual(dict(py_pkgs)["jinja2"], "3.1.2")

    def test_scan_result_scoring(self):
        res = ScanResult()
        res.findings = [
            Finding("F1", "Cat", Severity.CRITICAL, "d", "r"),
            Finding("F2", "Cat", Severity.HIGH, "d", "r"),
            Finding("F3", "Cat", Severity.MEDIUM, "d", "r"),
        ]
        res.calculate_score()
        # 100 - (1*25 + 1*12 + 1*6) = 100 - 43 = 57 -> Grade C
        self.assertEqual(res.security_score, 57)
        self.assertEqual(res.grade, "C")

    def test_api_spec_scanner(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            spec_path = os.path.join(tmpdir, "openapi.json")
            spec_data = {
                "openapi": "3.0.0",
                "info": {"title": "Sample API", "version": "1.0.0"},
                "paths": {
                    "/api/v1/admin/users": {
                        "get": {
                            "summary": "Admin Users List",
                            "responses": {"200": {"description": "OK"}}
                        }
                    },
                    "/api/v1/auth/login": {
                        "get": {
                            "summary": "User Login",
                            "parameters": [
                                {
                                    "name": "password",
                                    "in": "query",
                                    "schema": {"type": "string"}
                                }
                            ],
                            "responses": {"200": {"description": "OK"}}
                        }
                    },
                    "/api/v1/items": {
                        "get": {
                            "summary": "List all items",
                            "parameters": [],
                            "responses": {
                                "200": {
                                    "description": "Collection items",
                                    "content": {
                                        "application/json": {
                                            "schema": {"type": "array"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            with open(spec_path, "w", encoding="utf-8") as f:
                json.dump(spec_data, f)

            scanner = APISpecScanner(target_dir=tmpdir)
            findings = scanner.scan()

            self.assertTrue(len(findings) >= 3)
            titles = [f.title for f in findings]
            self.assertTrue(any("Missing Authentication" in t for t in titles))
            self.assertTrue(any("Query String" in t for t in titles))
            self.assertTrue(any("Pagination" in t for t in titles))

            for f in findings:
                self.assertIsNotNone(f.owasp_category)
                self.assertIsNotNone(f.poc_curl)

    def test_markdown_reporter_export(self):
        res = ScanResult(target_url="https://example.com")
        res.findings = [
            Finding(
                title="Missing Content-Security-Policy",
                category="Headers",
                severity=Severity.HIGH,
                description="CSP header is missing",
                remediation="Configure Content-Security-Policy header",
                cwe_id="CWE-1021",
                owasp_category="A05:2025-Security Misconfiguration",
                poc_curl="curl -sI https://example.com | grep -i content-security-policy",
            )
        ]
        res.calculate_score()

        with tempfile.TemporaryDirectory() as tmpdir:
            md_path = os.path.join(tmpdir, "report.md")
            reporter = MarkdownReporter(res)
            reporter.export(md_path)

            self.assertTrue(os.path.exists(md_path))
            with open(md_path, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertIn("SecAudit Enterprise Security Audit Report", content)
            self.assertIn("A05:2025-Security Misconfiguration", content)
            self.assertIn("curl -sI https://example.com", content)

    def test_sast_new_strix_rules_and_git_diff_filter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_py = os.path.join(tmpdir, "network.py")
            with open(file_py, "w", encoding="utf-8") as f:
                f.write(
                    """import requests
def fetch_user_data(user_url):
    return requests.get(user_url)

def read_custom_log(user_input):
    return open(f"/var/log/{user_input}", "r")
"""
                )

            file_js = os.path.join(tmpdir, "app.js")
            with open(file_js, "w", encoding="utf-8") as f:
                f.write(
                    """function handleUserUpdate(req, user) {
    Object.assign(user, req.body);
    target.__proto__ = req.body;
}
"""
                )

            # 1. Full scan
            scanner = SASTScanner(tmpdir)
            findings = scanner.scan()
            titles = [f.title for f in findings]

            self.assertTrue(any("SSRF" in t for t in titles))
            self.assertTrue(any("Path Traversal" in t for t in titles))
            self.assertTrue(any("Mass Assignment" in t for t in titles))
            self.assertTrue(any("Prototype Pollution" in t for t in titles))

            # 2. Diff-scoped scan: only target network.py
            diff_scanner = SASTScanner(tmpdir, target_files=[file_py])
            diff_findings = diff_scanner.scan()
            diff_titles = [f.title for f in diff_findings]

            self.assertTrue(any("SSRF" in t for t in diff_titles))
            self.assertFalse(any("Mass Assignment" in t for t in diff_titles))

    def test_html_reporter_export(self):
        res = ScanResult(target_url="https://example.com")
        res.findings = [
            Finding(
                title="Missing HSTS",
                category="Headers",
                severity=Severity.HIGH,
                description="HSTS missing",
                remediation="Add header",
                cwe_id="CWE-319",
                fix_snippet={"nginx": "add_header Strict-Transport-Security ...;", "apache": "Header always set ..."},
                poc_curl="curl -sI https://example.com",
                owasp_category="A05:2025-Security Misconfiguration",
            )
        ]
        res.calculate_score()

        with tempfile.TemporaryDirectory() as tmpdir:
            html_path = os.path.join(tmpdir, "dashboard.html")
            reporter = HTMLReporter(res)
            reporter.export(html_path)

            self.assertTrue(os.path.exists(html_path))
            with open(html_path, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertIn("stats-data", content)
            self.assertIn("findings-data", content)
            self.assertIn("JSON.parse", content)
            self.assertIn("display: block;", content)
            self.assertIn("display: none;", content)


if __name__ == "__main__":
    unittest.main()
