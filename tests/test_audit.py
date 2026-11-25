"""
Automated unit test suite for SecAudit 2.0 Enterprise
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
from sec_audit.scanners.cicd_scanner import CICDScanner
from sec_audit.scanners.graphql_scanner import GraphQLScanner
from sec_audit.scanners.jwt_scanner import JWTScanner
from sec_audit.scanners.websocket_scanner import WebSocketScanner
from sec_audit.scanners.ssti_scanner import SSTIScanner
from sec_audit.scanners.nosqli_scanner import NoSQLIScanner
from sec_audit.scanners.xxe_scanner import XXEScanner


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
        res = ScanResult(target_dir="/mock/project")
        res.volume_metrics.total_loc = 10000
        res.volume_metrics.total_files = 25
        res.findings = [
            Finding("F1", Category.SAST.value, Severity.CRITICAL, "d", "r"),
            Finding("F2", Category.SAST.value, Severity.HIGH, "d", "r"),
            Finding("F3", Category.SAST.value, Severity.MEDIUM, "d", "r"),
        ]
        res.calculate_score()
        # 1 Critical strictly caps the score at 69 -> Grade C
        self.assertEqual(res.security_score, 69)
        self.assertEqual(res.grade, "C")
        self.assertIsNotNone(res.pillar_scores)
        self.assertTrue(0 <= res.pillar_scores.sast_score <= 100)

    def test_volume_normalization_and_guardrails(self):
        # 1. Micro-project vs Enterprise scale with same defect count
        f1 = Finding("SQL Injection", Category.SAST.value, Severity.HIGH, "desc", "remed", cvss_score=8.5)
        f2 = Finding("DOM XSS", Category.SAST.value, Severity.MEDIUM, "desc", "remed", cvss_score=5.5)

        r_micro = ScanResult(target_dir="/mock/micro")
        r_micro.volume_metrics.total_loc = 250
        r_micro.volume_metrics.total_files = 2
        r_micro.findings = [f1, f2]
        r_micro.calculate_score()

        r_large = ScanResult(target_dir="/mock/large")
        r_large.volume_metrics.total_loc = 120000
        r_large.volume_metrics.total_files = 350
        r_large.findings = [f1, f2]
        r_large.calculate_score()

        # Defect density on large project is tiny -> score must be significantly higher
        self.assertTrue(r_large.security_score > r_micro.security_score)
        self.assertTrue(r_large.security_score >= 90)

        # 2. Critical guardrail ceiling on huge codebase
        r_huge_crit = ScanResult(target_dir="/mock/huge")
        r_huge_crit.volume_metrics.total_loc = 1000000
        r_huge_crit.volume_metrics.total_files = 2000
        r_huge_crit.findings = [
            Finding("Root Key Leak", Category.SAST.value, Severity.CRITICAL, "AWS Key", "Revoke", cvss_score=9.8)
        ]
        r_huge_crit.calculate_score()
        # Even with 1M LoC, 1 Critical exploit caps score at Grade C (<= 69)
        self.assertLessEqual(r_huge_crit.security_score, 69)
        self.assertEqual(r_huge_crit.grade, "C")

    def test_scanner_volume_metrics_tracking(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "service.py")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("""# Service file\n\nimport os\n\ndef run():\n    print('Hello World')\n    return True\n""")

            sast = SASTScanner(tmpdir)
            sast.scan()

            self.assertEqual(sast.scanned_files_count, 1)
            self.assertTrue(sast.scanned_loc >= 4)

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

    def test_sast_vendor_exclusion_and_clustering(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Vendor directory (should be skipped)
            vendor_dir = os.path.join(tmpdir, "public", "libs")
            os.makedirs(vendor_dir, exist_ok=True)
            with open(os.path.join(vendor_dir, "tailwindcss.js"), "w", encoding="utf-8") as f:
                f.write("eval('select * from users where id=' + id);\n")

            # 2. Minified file in root (should be skipped)
            with open(os.path.join(tmpdir, "bundle.min.js"), "w", encoding="utf-8") as f:
                f.write("eval('danger');\n")

            # 3. Client-side file with repetitive DOM XSS and fetch (SSRF should be skipped)
            public_js = os.path.join(tmpdir, "public", "js")
            os.makedirs(public_js, exist_ok=True)
            client_file = os.path.join(public_js, "app.js")
            with open(client_file, "w", encoding="utf-8") as f:
                # SSRF candidate in frontend (should be filtered out)
                f.write("fetch(url + '?id=' + id);\n")
                # 10 innerHTML assignments (should be clustered to 5)
                for i in range(10):
                    f.write(f"container.innerHTML = generateCard({i}) + '<br>';\n")

            scanner = SASTScanner(tmpdir)
            findings = scanner.scan()

            # Verify vendor files were excluded
            self.assertFalse(any("tailwindcss" in (f.location or "") for f in findings))
            self.assertFalse(any("bundle.min.js" in (f.location or "") for f in findings))

            # Verify SSRF was not flagged on frontend JS
            self.assertFalse(any("SSRF" in f.title for f in findings))

            # Verify DOM XSS was clustered
            xss_findings = [f for f in findings if "innerHTML" in f.title]
            self.assertEqual(len(xss_findings), 5)  # Capped at MAX_FINDINGS_PER_RULE_PER_FILE = 5
            self.assertTrue(xss_findings[-1].cluster_count > 1)
            self.assertIn("Clustered", xss_findings[-1].description)

    def test_clustered_scoring_fairness_and_guardrails(self):
        from sec_audit.models import VolumeMetrics

        # Scenario 1: Large repository (80 KLoC) with 20 clustered medium DOM findings
        res = ScanResult(
            target_dir="/mock/project",
            volume_metrics=VolumeMetrics(
                total_loc=80000,
                total_files=150,
                total_dependencies=200,
            ),
        )
        for i in range(20):
            res.findings.append(
                Finding(
                    title="Insecure document.write / innerHTML Assignment",
                    category=Category.SAST.value,
                    severity=Severity.MEDIUM,
                    description="DOM XSS",
                    remediation="Sanitize",
                    location=f"public/app_{i % 3}.js:{10 + i}",
                    cvss_score=5.5,
                )
            )
        res.calculate_score()
        # Should be a fair score (Grade B / >= 80%), not collapsing to 15%
        self.assertGreaterEqual(res.pillar_scores.sast_score, 80)
        self.assertGreaterEqual(res.security_score, 80)

        # Scenario 2: Project with 2 verified Critical exploits triggers guardrail
        res.findings.append(
            Finding(
                title="Hardcoded Production Private Key",
                category=Category.SAST.value,
                severity=Severity.CRITICAL,
                description="Leaked key",
                remediation="Rotate",
                cvss_score=9.8,
            )
        )
        res.findings.append(
            Finding(
                title="Remote Code Execution via Insecure Deserialization",
                category=Category.SAST.value,
                severity=Severity.CRITICAL,
                description="RCE",
                remediation="Use JSON",
                cvss_score=9.8,
            )
        )
        res.calculate_score()
        # Guardrail for 2 Criticals: composite ceiling <= 49 (Grade D)
        self.assertLessEqual(res.security_score, 49)
        self.assertIn(res.grade, ["D", "F"])

    def test_sca_lockfile_precedence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create both package.json and package-lock.json in same dir
            pkg_json = os.path.join(tmpdir, "package.json")
            with open(pkg_json, "w", encoding="utf-8") as f:
                json.dump({"dependencies": {"lodash": "^4.17.20", "express": "^4.18.0"}}, f)

            pkg_lock = os.path.join(tmpdir, "package-lock.json")
            with open(pkg_lock, "w", encoding="utf-8") as f:
                json.dump({
                    "packages": {
                        "node_modules/lodash": {"version": "4.17.21"},
                    }
                }, f)

            scanner = SCAScanner(tmpdir, check_online=False)
            scanner.scan()
            # Only 1 package from package-lock.json should be parsed, package.json must be skipped
            self.assertEqual(scanner.total_packages_count, 1)

    def test_sast_prototype_pollution_guard_exemption(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            code_file = os.path.join(tmpdir, "safe_proto.js")
            with open(code_file, "w", encoding="utf-8") as f:
                f.write("""
                // Legitimate key-validation guard against Prototype Pollution
                const blockedKeys = new Set(['__proto__', 'constructor', 'prototype']);
                function safeMerge(target, source) {
                    for (const key of Object.keys(source)) {
                        if (blockedKeys.has(key)) continue;
                        target[key] = source[key];
                    }
                }
                """)

            scanner = SASTScanner(tmpdir)
            findings = scanner.scan()
            proto_findings = [f for f in findings if "Prototype Pollution" in f.title]
            self.assertEqual(len(proto_findings), 0)

            # Now test genuine vulnerable sink
            vuln_file = os.path.join(tmpdir, "vuln_proto.js")
            with open(vuln_file, "w", encoding="utf-8") as f:
                f.write("""
                function unsafeAssign(obj, payload) {
                    obj.__proto__ = payload;
                }
                """)
            findings2 = scanner.scan()
            vuln_findings = [f for f in findings2 if "Prototype Pollution" in f.title]
            self.assertTrue(len(vuln_findings) >= 1)

    def test_sast_innerhtml_static_markup_exemption(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            code_file = os.path.join(tmpdir, "ui_helper.js")
            with open(code_file, "w", encoding="utf-8") as f:
                f.write("""
                // Pure static icons and markup loaders
                container.innerHTML = '<i class="fa fa-spinner fa-spin"></i>';
                badge.innerHTML = "<span class='badge bg-success'>OK</span>";
                """)

            scanner = SASTScanner(tmpdir)
            findings = scanner.scan()
            xss_findings = [f for f in findings if "innerHTML" in f.title]
            self.assertEqual(len(xss_findings), 0)

            # Test dynamic concatenation sink
            vuln_file = os.path.join(tmpdir, "vuln_ui.js")
            with open(vuln_file, "w", encoding="utf-8") as f:
                f.write("""
                function renderAlert(userInput) {
                    container.innerHTML = "<div class='alert'>" + userInput + "</div>";
                }
                """)
            findings2 = scanner.scan()
            vuln_findings = [f for f in findings2 if "innerHTML" in f.title]
            self.assertTrue(len(vuln_findings) >= 1)

    def test_sast_path_traversal_lookback_guard(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            guarded_file = os.path.join(tmpdir, "file_server.py")
            with open(guarded_file, "w", encoding="utf-8") as f:
                f.write("""
                import os
                def read_safe(user_filename):
                    base_dir = "/app/storage"
                    target = os.path.abspath(os.path.join(base_dir, user_filename))
                    if target.startswith(base_dir):
                        with open(target, "r") as f:
                            return f.read()
                """)

            scanner = SASTScanner(tmpdir)
            findings = scanner.scan()
            traversal_findings = [f for f in findings if "Path Traversal" in f.title]
            self.assertEqual(len(traversal_findings), 0)

            # Test unguarded path traversal
            unguarded_file = os.path.join(tmpdir, "vuln_server.py")
            with open(unguarded_file, "w", encoding="utf-8") as f:
                f.write("""
                def read_danger(user_filename):
                    with open(user_filename, "r") as f:
                        return f.read()
                """)
            findings2 = scanner.scan()
            unguarded_findings = [f for f in findings2 if "Path Traversal" in f.title]
            self.assertTrue(len(unguarded_findings) >= 1)

    def test_continuous_asymptotic_risk_ceiling(self):
        from sec_audit.models import VolumeMetrics

        # Calculate scores for 9 Highs vs 10 Highs
        def create_scan_with_highs(count: int) -> ScanResult:
            res = ScanResult(
                target_dir="/mock",
                volume_metrics=VolumeMetrics(total_loc=100000, total_files=200, total_dependencies=300),
            )
            for i in range(count):
                res.findings.append(
                    Finding(
                        title=f"High Risk Flaw {i}",
                        category=Category.SAST.value,
                        severity=Severity.HIGH,
                        description="High issue",
                        remediation="Fix it",
                        cvss_score=8.0,
                    )
                )
            res.calculate_score()
            return res

        r9 = create_scan_with_highs(9)
        r10 = create_scan_with_highs(10)

        # Difference should be smooth (smooth decay ~ 1-2 points), not a 5-point sudden cliff
        score_diff = r9.security_score - r10.security_score
        self.assertLessEqual(score_diff, 2)
        self.assertGreaterEqual(score_diff, 0)

    def test_sca_smart_severity_mapping(self):
        scanner = SCAScanner("/mock", check_online=False)

        # 1. Unmaintained advisory
        vuln_unm = {
            "id": "GHSA-unm",
            "summary": "This package is unmaintained and deprecated",
            "database_specific": {"informational": "unmaintained"},
        }
        f1 = scanner._parse_osv_vuln(vuln_unm, "old-pkg", "1.0.0", "package.json")
        self.assertEqual(f1.severity, Severity.LOW)
        self.assertEqual(f1.cvss_score, 3.5)

        # 2. Unrated advisory (defaults safely to MEDIUM 5.0)
        vuln_unrated = {
            "id": "GHSA-unrated",
            "summary": "Some vulnerability without CVSS or database severity",
        }
        f2 = scanner._parse_osv_vuln(vuln_unrated, "pkg-b", "2.0.0", "package.json")
        self.assertEqual(f2.severity, Severity.MEDIUM)
        self.assertEqual(f2.cvss_score, 5.0)

    def test_sast_docstring_and_entropy_false_positive_elimination(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sample_file = os.path.join(tmpdir, "docstring_and_placeholders.py")
            with open(sample_file, "w", encoding="utf-8") as f:
                f.write('''
"""
Documentation and docstring example:
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
dummy_key = "sk-1234567890abcdef1234567890abcdef"
"""

# Low-entropy dummy placeholder outside docstring
placeholder_token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
dummy_token_2 = "ghp_000000000000000000000000000000000000"

# Genuine high-entropy secret
real_secret = "ghp_4Z9qX2mL8wR1vT7yP0sK3jN6bC5aE8dF1gH2"
''')
            scanner = SASTScanner(tmpdir)
            findings = scanner.scan()

            # Ensure docstring SQLi and dummy low-entropy placeholders are not flagged
            sqli_findings = [f for f in findings if "SQL Injection" in f.title]
            self.assertEqual(len(sqli_findings), 0)

            # Ensure genuine high-entropy secret was flagged
            secret_findings = [f for f in findings if "Secret" in f.title or "Token" in f.title]
            self.assertEqual(len(secret_findings), 1)
            self.assertIn("real_secret", secret_findings[0].evidence or "")

    def test_sast_static_origin_ssrf_suppression(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            safe_file = os.path.join(tmpdir, "safe_client.py")
            with open(safe_file, "w", encoding="utf-8") as f:
                f.write('''
import requests

def fetch_data(item_id):
    url = f"https://api.osv.dev/v1/vulns/{item_id}"
    return requests.get(url)
''')
            vuln_file = os.path.join(tmpdir, "vuln_client.py")
            with open(vuln_file, "w", encoding="utf-8") as f:
                f.write('''
import requests

def proxy_request(user_input):
    return requests.get(user_input)
''')
            scanner = SASTScanner(tmpdir)
            findings = scanner.scan()

            ssrf_findings = [f for f in findings if "SSRF" in f.title or "Request Forgery" in f.title]
            # Only the unvalidated dynamic URL should trigger SSRF, not the static origin
            self.assertEqual(len(ssrf_findings), 1)
            self.assertIn("vuln_client.py", ssrf_findings[0].location)

    def test_cicd_scanner_pwn_request_and_script_injection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wf_dir = os.path.join(tmpdir, ".github", "workflows")
            os.makedirs(wf_dir, exist_ok=True)
            wf_path = os.path.join(wf_dir, "ci.yml")
            with open(wf_path, "w", encoding="utf-8") as f:
                f.write('''
name: Insecure CI
on: pull_request_target

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Print Title
        run: echo "${{ github.event.issue.title }}"
      - uses: actions/setup-node@v2
''')
            scanner = CICDScanner(tmpdir)
            findings = scanner.scan()

            titles = [f.title for f in findings]
            self.assertTrue(any("PwnRequest" in t for t in titles))
            self.assertTrue(any("Script Injection" in t for t in titles))
            self.assertTrue(any("Unpinned Action" in t for t in titles))

    def test_graphql_scanner_local_schema(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            schema_path = os.path.join(tmpdir, "schema.graphql")
            with open(schema_path, "w", encoding="utf-8") as f:
                f.write('''
type User {
  id: ID!
  name: String!
  friends: [User]
}
''')
            scanner = GraphQLScanner(target_dir=tmpdir)
            findings = scanner.scan()

            self.assertTrue(len(findings) >= 1)
            self.assertTrue(any("Recursive GraphQL Schema" in f.title for f in findings))

    def test_jwt_scanner_rules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            auth_py = os.path.join(tmpdir, "auth.py")
            with open(auth_py, "w", encoding="utf-8") as f:
                f.write('''
import jwt

def parse_token(raw_token):
    return jwt.decode(raw_token, algorithms=["none"], verify_signature=False)

def verify_token(raw_token):
    return jwt.decode(raw_token, "secret", algorithms=["HS256"])
''')
            scanner = JWTScanner(tmpdir)
            findings = scanner.scan()

            titles = [f.title for f in findings]
            self.assertTrue(any("none" in t.lower() for t in titles))
            self.assertTrue(any("Weak Hardcoded JWT Secret" in t or "Weak Hardcoded Secret" in t for t in titles))

    def test_iac_terraform_auditor(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tf_path = os.path.join(tmpdir, "main.tf")
            with open(tf_path, "w", encoding="utf-8") as f:
                f.write('''
provider "aws" {
  access_key = "AKIA1234567890123456"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-test-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "allow_ssh" {
  name = "allow_ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "unencrypted_vol" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = false
}
''')
            scanner = IaCScanner(tmpdir)
            findings = scanner.scan()

            titles = [f.title for f in findings]
            self.assertTrue(any("Hardcoded Credentials" in t for t in titles))
            self.assertTrue(any("Public Read" in t for t in titles))
            self.assertTrue(any("SSH (22)" in t for t in titles))
            self.assertTrue(any("Encryption Disabled" in t for t in titles))

    def test_websocket_scanner_rules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            client_file = os.path.join(tmpdir, "client.js")
            with open(client_file, "w", encoding="utf-8") as f:
                f.write('''
const socket = new WebSocket("ws://api.example.com/live");
''')
            server_file = os.path.join(tmpdir, "server.js")
            with open(server_file, "w", encoding="utf-8") as f:
                f.write('''
const wss = new WebSocket.Server({ port: 8080, verifyClient: false });
''')
            scanner = WebSocketScanner(tmpdir)
            findings = scanner.scan()

            titles = [f.title for f in findings]
            self.assertTrue(any("Unencrypted WebSocket" in t for t in titles))
            self.assertTrue(any("Missing Origin Validation" in t for t in titles))

    def test_ssti_scanner_jinja_and_node(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            flask_app = os.path.join(tmpdir, "app.py")
            with open(flask_app, "w", encoding="utf-8") as f:
                f.write('''
from flask import render_template_string

def render_page(user_input):
    return render_template_string(f"Hello {user_input}")

def safe_render():
    return render_template_string("<h1>Welcome Home</h1>")
''')
            node_app = os.path.join(tmpdir, "server.js")
            with open(node_app, "w", encoding="utf-8") as f:
                f.write('''
const ejs = require('ejs');
function handleReq(req, res) {
    const html = ejs.render(req.query.template);
}
''')
            scanner = SSTIScanner(target_dir=tmpdir)
            findings = scanner.scan()

            titles = [f.title for f in findings]
            self.assertTrue(any("Jinja2" in t for t in titles))
            self.assertTrue(any("Node.js" in t for t in titles))
            # Verify counterevidence: safe_render should not trigger a finding
            self.assertEqual(len(findings), 2)

    def test_nosqli_scanner_raw_payload_and_where(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vuln_route = os.path.join(tmpdir, "auth.js")
            with open(vuln_route, "w", encoding="utf-8") as f:
                f.write('''
app.post('/login', async (req, res) => {
    const user = await User.findOne(req.body);
    const data = await collection.find({ $where: "this.name == '" + user_input + "'" });
});
''')
            safe_route = os.path.join(tmpdir, "safe_auth.js")
            with open(safe_route, "w", encoding="utf-8") as f:
                f.write('''
const sanitize = require('mongo-sanitize');
app.post('/safe-login', async (req, res) => {
    const clean = sanitize(req.body);
    const user = await User.findOne(clean);
});
''')
            scanner = NoSQLIScanner(target_dir=tmpdir)
            findings = scanner.scan()

            titles = [f.title for f in findings]
            self.assertTrue(any("Raw Request Payload" in t for t in titles))
            self.assertTrue(any("$where" in t for t in titles))
            # Safe route should have been suppressed by mongo-sanitize counterevidence
            safe_findings = [f for f in findings if "safe_auth.js" in f.location]
            self.assertEqual(len(safe_findings), 0)

    def test_xxe_scanner_lxml_and_doctype(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            vuln_py = os.path.join(tmpdir, "parser.py")
            with open(vuln_py, "w", encoding="utf-8") as f:
                f.write('''
from lxml import etree
parser = etree.XMLParser(resolve_entities=True)
''')
            vuln_xml = os.path.join(tmpdir, "test.xml")
            with open(vuln_xml, "w", encoding="utf-8") as f:
                f.write('''<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
''')
            safe_py = os.path.join(tmpdir, "safe_parser.py")
            with open(safe_py, "w", encoding="utf-8") as f:
                f.write('''
import defusedxml.lxml as defused_etree
parser = defused_etree.XMLParser()
''')
            scanner = XXEScanner(target_dir=tmpdir)
            findings = scanner.scan()

            titles = [f.title for f in findings]
            self.assertTrue(any("Python lxml" in t for t in titles))
            self.assertTrue(any("DOCTYPE SYSTEM" in t for t in titles))
            # defusedxml should be suppressed
            safe_findings = [f for f in findings if "safe_parser.py" in f.location]
            self.assertEqual(len(safe_findings), 0)

    def test_strix_closure_state_and_sarif_properties(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sarif_file = os.path.join(tmpdir, "results.sarif")
            res = ScanResult(target_dir=tmpdir)
            res.findings.append(
                Finding(
                    title="Verified RCE Flaw",
                    category=Category.SAST.value,
                    severity=Severity.CRITICAL,
                    description="RCE vulnerability",
                    remediation="Patch input",
                    cvss_score=9.8,
                    closure_state="CONFIRMED",
                    poc_curl="curl -s 'http://localhost/test?cmd=whoami'",
                    counterevidence="No sanitize middleware present",
                    location="app.py:10",
                )
            )
            reporter = SARIFReporter(res)
            reporter.export(sarif_file)

            with open(sarif_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            sarif_results = data["runs"][0]["results"]
            self.assertEqual(len(sarif_results), 1)
            props = sarif_results[0].get("properties", {})
            self.assertEqual(props.get("closure_state"), "CONFIRMED")
            self.assertIn("curl", props.get("poc_curl", ""))
            self.assertEqual(props.get("counterevidence"), "No sanitize middleware present")




if __name__ == "__main__":
    unittest.main()
