"""
SecAudit 2.0 Enterprise Orchestrator
Coordinates multithreaded scanning across DAST, Network, SAST, IaC, SCA, and License engines.
"""

import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List
from .models import ScanResult, Severity, Finding
from .scanners import (
    HeaderScanner,
    SSLScanner,
    DNSScanner,
    TechDetector,
    CORSMethodsScanner,
    SensitiveFilesScanner,
    SASTScanner,
    IaCScanner,
    SCAScanner,
    LicenseScanner,
    APISpecScanner,
)


class SecAuditOrchestrator:
    """
    Coordinates and executes multithreaded security audits across web endpoints, APIs, and codebases.
    Supports Git diff-scoped scanning and OpenAPI/Swagger specifications.
    """

    SEVERITY_ORDER = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 1,
        Severity.MEDIUM.value: 2,
        Severity.LOW.value: 3,
        Severity.INFO.value: 4,
    }

    def __init__(
        self,
        target_url: Optional[str] = None,
        target_dir: Optional[str] = None,
        check_online_sca: bool = True,
        timeout: int = 10,
        max_workers: int = 6,
        diff_mode: bool = False,
        diff_base: Optional[str] = None,
    ):
        self.target_url = target_url
        self.target_dir = target_dir
        self.check_online_sca = check_online_sca
        self.timeout = timeout
        self.max_workers = max_workers
        self.diff_mode = diff_mode
        self.diff_base = diff_base

    def _get_git_diff_files(self) -> Optional[List[str]]:
        """
        Extracts changed files in the Git repository for targeted diff review.
        """
        if not self.target_dir or not os.path.exists(self.target_dir):
            return None

        cmd = ["git", "diff", "--name-only"]
        if self.diff_base:
            cmd.append(self.diff_base)
        else:
            cmd.append("HEAD")

        try:
            res = subprocess.run(
                cmd,
                cwd=self.target_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                files = [
                    os.path.join(self.target_dir, line.strip())
                    for line in res.stdout.splitlines()
                    if line.strip()
                ]
                return files
        except Exception:
            pass
        return None

    def run(self) -> ScanResult:
        result = ScanResult(
            target_url=self.target_url,
            target_dir=self.target_dir,
        )

        start_time = time.time()
        all_findings: List[Finding] = []

        # Determine git diff files if diff mode is enabled
        target_files = None
        if self.diff_mode or self.diff_base:
            target_files = self._get_git_diff_files()

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_tasks = {}

            # 1. Dispatch DAST & Network Scanners
            if self.target_url:
                header_scanner = HeaderScanner(self.target_url, timeout=self.timeout)
                future_tasks[executor.submit(header_scanner.scan)] = "Headers"

                ssl_scanner = SSLScanner(self.target_url, timeout=self.timeout)
                future_tasks[executor.submit(ssl_scanner.scan)] = "SSL/TLS"

                files_scanner = SensitiveFilesScanner(self.target_url, timeout=self.timeout)
                future_tasks[executor.submit(files_scanner.scan)] = "Sensitive Files"

                dns_scanner = DNSScanner(self.target_url, timeout=self.timeout)
                future_tasks[executor.submit(dns_scanner.scan)] = "DNS Security"

                cors_scanner = CORSMethodsScanner(self.target_url, timeout=self.timeout)
                future_tasks[executor.submit(cors_scanner.scan)] = "HTTP Methods & CORS"

                tech_detector = TechDetector(self.target_url, timeout=self.timeout)
                future_tasks[executor.submit(tech_detector.detect)] = "Tech Detector"

            # 2. Dispatch API Specification Scanner (OpenAPI / Swagger)
            if self.target_dir or self.target_url:
                api_scanner = APISpecScanner(
                    target_dir=self.target_dir,
                    target_url=self.target_url,
                    timeout=self.timeout,
                )
                future_tasks[executor.submit(api_scanner.scan)] = "API Spec"

            # 3. Dispatch SAST, IaC, SCA & License Scanners
            if self.target_dir:
                sast_scanner = SASTScanner(self.target_dir, target_files=target_files)
                future_tasks[executor.submit(sast_scanner.scan)] = "SAST"

                iac_scanner = IaCScanner(self.target_dir)
                future_tasks[executor.submit(iac_scanner.scan)] = "IaC"

                sca_scanner = SCAScanner(self.target_dir, check_online=self.check_online_sca, timeout=self.timeout)
                future_tasks[executor.submit(sca_scanner.scan)] = "SCA"

                lic_scanner = LicenseScanner(self.target_dir)
                future_tasks[executor.submit(lic_scanner.scan)] = "License"

            # 4. Collect Results
            for future in as_completed(future_tasks):
                task_name = future_tasks[future]
                try:
                    res = future.result()
                    if task_name == "Tech Detector":
                        result.detected_tech = res
                    elif task_name == "License":
                        lic_findings, lic_summary = res
                        all_findings.extend(lic_findings)
                        result.license_summary = lic_summary
                    elif isinstance(res, list):
                        all_findings.extend(res)
                except Exception:
                    pass

        # Sort findings by severity
        all_findings.sort(key=lambda f: self.SEVERITY_ORDER.get(f.severity.value, 99))

        result.findings = all_findings
        result.duration_seconds = time.time() - start_time
        result.calculate_score()
        return result
