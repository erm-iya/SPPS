from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import math
from typing import List, Optional, Dict, Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(str, Enum):
    HEADERS = "Security Headers & Cookies"
    CSP = "Content Security Policy (CSP)"
    SSL_TLS = "SSL/TLS & Encryption"
    DNS_EMAIL = "DNS & Email Security (SPF/DMARC/CAA)"
    EXPOSED_FILES = "Sensitive Files & Endpoints"
    HTTP_METHODS_CORS = "HTTP Methods & CORS Security"
    TECH_STACK = "Technology & Server Fingerprint"
    SAST = "Static Source Code Analysis"
    IAC = "Infrastructure as Code (Docker/K8s/Terraform)"
    SCA = "Dependency Vulnerabilities"
    LICENSE = "License Compliance"
    API = "API Security & OpenAPI Specifications"
    CICD = "CI/CD & Pipeline Security"
    GRAPHQL = "GraphQL & API Query Security"
    JWT = "JWT & Authentication Security"
    WEBSOCKET = "WebSocket & Real-Time Security"
    SSTI = "Server-Side Template Injection (SSTI)"
    NOSQLI = "NoSQL & Document DB Injection"
    XXE = "XML External Entity (XXE) Processing"


class OWASP2025(str, Enum):
    A01 = "A01:2025-Broken Access Control & SSRF"
    A02 = "A02:2025-Security Misconfiguration"
    A03 = "A03:2025-Software Supply Chain Failures"
    A04 = "A04:2025-Cryptographic Failures"
    A05 = "A05:2025-Injection"
    A06 = "A06:2025-Insecure Design"
    A07 = "A07:2025-Authentication Failures"
    A08 = "A08:2025-Software and Data Integrity Failures"
    A09 = "A09:2025-Security Logging and Alerting Failures"
    A10 = "A10:2025-Mishandling of Exceptional Conditions"


@dataclass
class Finding:
    title: str
    category: str
    severity: Severity
    description: str
    remediation: str
    evidence: Optional[str] = None
    location: Optional[str] = None
    cwe_id: Optional[str] = None
    reference: Optional[str] = None
    cvss_score: Optional[float] = None
    fix_snippet: Optional[Dict[str, str]] = None  # e.g. {"nginx": "...", "apache": "...", "express": "..."}
    poc_curl: Optional[str] = None  # Strix-style reproducible PoC curl command
    owasp_category: Optional[str] = None  # OWASP Top 10:2025 classification
    cluster_count: int = 1  # Number of consolidated occurrences of this pattern in the same file
    closure_state: str = "CONFIRMED"  # Strix closure discipline: CONFIRMED, RULED_OUT, NEEDS_REVIEW
    counterevidence: Optional[str] = None  # Specific control rationale or proof gap explanation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "location": self.location,
            "cwe_id": self.cwe_id,
            "reference": self.reference,
            "cvss_score": self.cvss_score,
            "fix_snippet": self.fix_snippet,
            "poc_curl": self.poc_curl,
            "owasp_category": self.owasp_category,
            "cluster_count": self.cluster_count,
            "closure_state": self.closure_state,
            "counterevidence": self.counterevidence,
        }


@dataclass
class VolumeMetrics:
    """
    Project scale and attack surface inventory metrics used for normalization.
    """
    total_loc: int = 0
    total_files: int = 0
    total_dependencies: int = 0
    total_endpoints: int = 0
    total_manifests: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_loc": self.total_loc,
            "total_files": self.total_files,
            "total_dependencies": self.total_dependencies,
            "total_endpoints": self.total_endpoints,
            "total_manifests": self.total_manifests,
        }


@dataclass
class PillarScores:
    """
    Individual security domain sub-scores (0-100) and composite enterprise grade.
    """
    sast_score: int = 100
    sca_score: int = 100
    iac_score: int = 100
    dast_score: int = 100
    composite_score: int = 100

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sast_score": self.sast_score,
            "sca_score": self.sca_score,
            "iac_score": self.iac_score,
            "dast_score": self.dast_score,
            "composite_score": self.composite_score,
        }


@dataclass
class ScanResult:
    target_url: Optional[str] = None
    target_dir: Optional[str] = None
    scan_date: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    duration_seconds: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)
    owasp_summary: Dict[str, int] = field(default_factory=dict)
    detected_tech: List[Dict[str, str]] = field(default_factory=list)  # e.g. [{"name": "React", "category": "Frontend"}]
    license_summary: Dict[str, int] = field(default_factory=dict)
    volume_metrics: VolumeMetrics = field(default_factory=VolumeMetrics)
    pillar_scores: PillarScores = field(default_factory=PillarScores)
    security_score: int = 100
    grade: str = "A+"

    @staticmethod
    def _compute_finding_weight(f: Finding) -> float:
        """
        Compute effective finding risk weight using base CVSS score and exploitability factor.
        """
        if f.cvss_score is not None and f.cvss_score > 0:
            base_cvss = float(f.cvss_score)
        else:
            default_weights = {
                Severity.CRITICAL.value: 9.5,
                Severity.HIGH.value: 7.8,
                Severity.MEDIUM.value: 5.3,
                Severity.LOW.value: 2.5,
                Severity.INFO.value: 0.0,
            }
            base_cvss = default_weights.get(f.severity.value, 5.0)

        # Exploitability & Blast Radius Multipliers
        title_desc = f"{f.title} {f.description}".lower()
        if any(kw in title_desc for kw in [
            "rce", "remote code execution", "deserialization", "sql injection",
            "secret", "token", "password", "api key", "private key", "ssrf",
            "broken access control", "bola", "unauthenticated admin", "privileged"
        ]):
            exploit_multiplier = 1.35
        elif any(kw in title_desc for kw in [
            "referrer-policy", "permissions-policy", "pseudo-random", "unpinned",
            "pagination", "debug mode"
        ]):
            exploit_multiplier = 0.55
        else:
            exploit_multiplier = 1.0

        return base_cvss * exploit_multiplier

    def calculate_score(self) -> None:
        """
        Enterprise Defect Density & CVSS-Weighted Scoring Engine.
        Normalizes penalties by project scale (KLoC, file count, package count, endpoints tested)
        while enforcing hard risk ceilings for verified critical exploits.
        """
        counts = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0,
        }
        owasp_counts = {}

        # Segregate findings into 4 core security pillars
        sast_findings: List[Finding] = []
        sca_findings: List[Finding] = []
        iac_findings: List[Finding] = []
        dast_findings: List[Finding] = []

        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
            if f.owasp_category:
                owasp_counts[f.owasp_category] = owasp_counts.get(f.owasp_category, 0) + 1

            cat = f.category
            if cat in [Category.SAST.value, Category.JWT.value, Category.SSTI.value, Category.NOSQLI.value, Category.XXE.value]:
                sast_findings.append(f)
            elif cat in [Category.SCA.value, Category.LICENSE.value]:
                sca_findings.append(f)
            elif cat in [Category.IAC.value, Category.CICD.value]:
                iac_findings.append(f)
            else:
                dast_findings.append(f)

        self.stats = counts
        self.owasp_summary = owasp_counts

        # -------------------------------------------------------------
        # Pillar 1: Source Code & Secrets (SAST) - Clustered Defect Density
        # -------------------------------------------------------------
        kloc = max(0.5, self.volume_metrics.total_loc / 1000.0) if self.volume_metrics.total_loc > 0 else max(1.0, self.volume_metrics.total_files * 0.1)
        sast_scale = math.sqrt(kloc)

        # Group SAST findings by (title, file) to eliminate repetitive pattern saturation
        sast_groups: Dict[Tuple[str, str], List[Finding]] = {}
        for f in sast_findings:
            fpath = f.location.split(":")[0] if f.location else "unknown"
            sast_groups.setdefault((f.title, fpath), []).append(f)

        sast_total_weight = 0.0
        for (title, fpath), group in sast_groups.items():
            base_w = self._compute_finding_weight(group[0])
            total_occurrences = sum(getattr(f, "cluster_count", 1) for f in group)
            # Logarithmic dampening: first occurrence carries full weight, subsequent instances in same file dampen
            diminishing = 1.0 + 0.35 * math.log(max(1, total_occurrences))
            sast_total_weight += base_w * diminishing

        sast_penalty = min(85.0, (sast_total_weight / sast_scale) * 0.55)
        sast_score = int(round(max(0.0, 100.0 - sast_penalty)))

        # -------------------------------------------------------------
        # Pillar 2: Dependencies & Supply Chain (SCA) - Package-Level Risk
        # -------------------------------------------------------------
        pkgs_count = max(1, self.volume_metrics.total_dependencies)

        # Group SCA findings by package identifier
        sca_pkg_groups: Dict[str, List[Finding]] = {}
        for f in sca_findings:
            pkg_key = f.location or f.title
            sca_pkg_groups.setdefault(pkg_key, []).append(f)

        sca_total_weight = 0.0
        for pkg_key, group in sca_pkg_groups.items():
            max_cvss = max(self._compute_finding_weight(f) for f in group)
            # Incremental risk for multiple CVEs on the exact same package version
            incremental = min(3.0, (len(group) - 1) * 0.30)
            is_transitive = "lock" in pkg_key.lower()
            transitive_multiplier = 0.7 if is_transitive else 1.0
            sca_total_weight += (max_cvss + incremental) * transitive_multiplier

        distinct_vuln_pkgs = len(sca_pkg_groups)
        vuln_pkg_ratio = min(1.0, distinct_vuln_pkgs / float(pkgs_count))
        sca_scale = math.sqrt(pkgs_count)
        sca_penalty = min(85.0, ((sca_total_weight / sca_scale) * 2.5) + (vuln_pkg_ratio * 25.0))
        sca_score = int(round(max(0.0, 100.0 - sca_penalty)))

        # -------------------------------------------------------------
        # Pillar 3: Infrastructure as Code (IaC) - Scaled by Manifest Count
        # -------------------------------------------------------------
        manifests = max(1, self.volume_metrics.total_manifests or 1)
        iac_total_weight = sum(self._compute_finding_weight(f) for f in iac_findings)
        iac_penalty = min(85.0, (iac_total_weight / math.sqrt(manifests)) * 2.8)
        iac_score = int(round(max(0.0, 100.0 - iac_penalty)))

        # -------------------------------------------------------------
        # Pillar 4: Web & Network Attack Surface (DAST/API) - Scaled by Endpoints
        # -------------------------------------------------------------
        endpoints = max(1, self.volume_metrics.total_endpoints or (8 if self.target_url else 1))
        dast_total_weight = sum(self._compute_finding_weight(f) for f in dast_findings)
        dast_penalty = min(85.0, (dast_total_weight / math.sqrt(endpoints)) * 1.8)
        dast_score = int(round(max(0.0, 100.0 - dast_penalty)))

        # -------------------------------------------------------------
        # Dynamic Pillar Weighting & Composite Aggregation
        # -------------------------------------------------------------
        active_pillars: Dict[str, float] = {}
        if self.target_dir:
            active_pillars["sast"] = 0.50
            if self.volume_metrics.total_dependencies > 0 or sca_findings:
                active_pillars["sca"] = 0.35
            if self.volume_metrics.total_manifests > 0 or iac_findings:
                active_pillars["iac"] = 0.15

        if self.target_url or any(f.category == Category.API.value for f in self.findings):
            active_pillars["dast"] = 0.35
            # Rebalance existing weights if combined with source
            if "sast" in active_pillars:
                active_pillars["sast"] = 0.35
                active_pillars["sca"] = 0.20
                active_pillars["iac"] = 0.10

        if not active_pillars:
            active_pillars["sast"] = 1.0

        # Normalize weights to sum to 1.0
        total_weight_sum = sum(active_pillars.values())
        norm_weights = {k: v / total_weight_sum for k, v in active_pillars.items()}

        composite = (
            norm_weights.get("sast", 0.0) * sast_score
            + norm_weights.get("sca", 0.0) * sca_score
            + norm_weights.get("iac", 0.0) * iac_score
            + norm_weights.get("dast", 0.0) * dast_score
        )

        # -------------------------------------------------------------
        # Absolute Risk Ceilings (Guardrails)
        # Prevents critical exploits from being masked by sheer code volume
        # -------------------------------------------------------------
        c_count = counts[Severity.CRITICAL.value]
        h_count = counts[Severity.HIGH.value]

        if c_count >= 4:
            composite = min(composite, 25.0)  # Grade F
        elif c_count >= 2:
            composite = min(composite, 49.0)  # Grade D
        elif c_count >= 1:
            composite = min(composite, 69.0)  # Grade C
        elif h_count > 0 and c_count == 0:
            # Smooth asymptotic ceiling preventing abrupt step-function cliffs
            asymptotic_ceiling = 100.0 - 30.0 * (1.0 - math.exp(-0.06 * h_count))
            composite = min(composite, asymptotic_ceiling)

        final_composite = int(round(max(0.0, min(100.0, composite))))

        self.pillar_scores = PillarScores(
            sast_score=sast_score,
            sca_score=sca_score,
            iac_score=iac_score,
            dast_score=dast_score,
            composite_score=final_composite,
        )

        self.security_score = final_composite

        if self.security_score >= 95:
            self.grade = "A+"
        elif self.security_score >= 85:
            self.grade = "A"
        elif self.security_score >= 70:
            self.grade = "B"
        elif self.security_score >= 50:
            self.grade = "C"
        elif self.security_score >= 30:
            self.grade = "D"
        else:
            self.grade = "F"

    def to_dict(self) -> Dict[str, Any]:
        self.calculate_score()
        return {
            "target_url": self.target_url,
            "target_dir": self.target_dir,
            "scan_date": self.scan_date,
            "duration_seconds": round(self.duration_seconds, 2),
            "security_score": self.security_score,
            "grade": self.grade,
            "stats": self.stats,
            "owasp_summary": self.owasp_summary,
            "detected_tech": self.detected_tech,
            "license_summary": self.license_summary,
            "volume_metrics": self.volume_metrics.to_dict(),
            "pillar_scores": self.pillar_scores.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
        }
