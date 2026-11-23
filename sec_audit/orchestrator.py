"""
SecAudit 2.0 Enterprise Orchestrator
Coordinates multithreaded scanning across DAST, Network, SAST, IaC, SCA, and License engines.
"""

import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Callable
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
        progress_callback: Optional[Callable[[int, str], None]] = None,
        check_interrupted: Optional[Callable[[], None]] = None,
    ):
        self.target_url = target_url
        self.target_dir = target_dir
        self.check_online_sca = check_online_sca
        self.timeout = timeout
        self.max_workers = max_workers
        self.diff_mode = diff_mode
        self.diff_base = diff_base
        self.progress_callback = progress_callback
        self.check_interrupted = check_interrupted

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

        api_scanner = None
        sast_scanner = None
        iac_scanner = None
        sca_scanner = None

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
            total_tasks = len(future_tasks)
            completed_count = 0
            if self.progress_callback:
                self.progress_callback(5, f"Dispatched {total_tasks} parallel security engines...")

            for future in as_completed(future_tasks):
                if self.check_interrupted:
                    self.check_interrupted()

                completed_count += 1
                task_name = future_tasks[future]
                if self.progress_callback and total_tasks > 0:
                    pct = 5 + int((completed_count / total_tasks) * 90)
                    self.progress_callback(pct, f"Completed scanning: {task_name}")

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

        if self.progress_callback:
            self.progress_callback(98, "Calculating security score and finalizing metrics...")

        # Sort findings by severity
        all_findings.sort(key=lambda f: self.SEVERITY_ORDER.get(f.severity.value, 99))

        # Aggregate project volume and inventory metrics for normalization
        if sast_scanner:
            result.volume_metrics.total_loc = sast_scanner.scanned_loc
            result.volume_metrics.total_files = sast_scanner.scanned_files_count
        if sca_scanner:
            result.volume_metrics.total_dependencies = sca_scanner.total_packages_count
        if iac_scanner:
            result.volume_metrics.total_manifests = iac_scanner.manifests_count

        total_endpoints = 0
        if self.target_url:
            total_endpoints += 8  # Standard DAST probe count (headers, ssl, dns, cors, sensitive files)
        if api_scanner:
            total_endpoints += api_scanner.total_routes_count
        result.volume_metrics.total_endpoints = total_endpoints

        result.findings = all_findings
        result.duration_seconds = time.time() - start_time
        result.calculate_score()
        return result
