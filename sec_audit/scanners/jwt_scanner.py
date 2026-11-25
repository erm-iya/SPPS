"""
JWT (JSON Web Token) Security & Authentication Auditor
Detects 'none' algorithm acceptance, dictionary HMAC secrets, missing expiration, and algorithm confusion.
"""

import os
import re
from typing import List
from ..models import Finding, Severity, Category
from ..config import SAST_EXTENSIONS
from ..ignore_matcher import IgnoreMatcher


class JWTScanner:
    """
    Scans application source code across multiple languages for JWT implementation flaws.
    """

    WEAK_HMAC_SECRETS = {
        "secret", "secretkey", "jwtsecret", "jwt_secret", "123456", "password",
        "admin", "app_secret", "mysecret", "test", "development", "changeme",
        "supersecret", "keyboardcat",
    }

    PATTERNS = [
        # 1. Insecure 'none' algorithm or disabled signature verification
        {
            "id": "JWT-NONE-ALG",
            "name": "JWT Insecure 'none' Algorithm or Signature Verification Disabled",
            "severity": Severity.CRITICAL,
            "cvss": 9.8,
            "regex": re.compile(
                r"""(?i)(?:algorithms?\s*[:=]\s*\[?\s*['"]none['"]|verify_signature\s*[:=]\s*False|verify_signature\s*:\s*false)"""
            ),
            "description": "JWT signature verification explicitly disabled or configured to accept the 'none' algorithm. Attackers can forge arbitrary authentication tokens with modified user IDs or administrator claims.",
            "remediation": "Never accept the 'none' algorithm. Always enforce cryptographic signature verification with a strict algorithm whitelist (e.g. ['RS256'] or ['HS256']).",
            "cwe": "CWE-347",
            "owasp": "A07:2025-Authentication Failures",
        },
        # 2. Disabled expiration verification
        {
            "id": "JWT-NO-EXP",
            "name": "JWT Expiration Check Disabled (Replay Risk)",
            "severity": Severity.MEDIUM,
            "cvss": 5.0,
            "regex": re.compile(
                r"""(?i)(?:ignoreExpiration\s*[:=]\s*true|verify_exp\s*[:=]\s*False|verify_exp\s*:\s*false)"""
            ),
            "description": "JWT expiration verification is explicitly disabled, allowing leaked, stolen, or revoked tokens to be accepted indefinitely.",
            "remediation": "Enable strict expiration checks and ensure short-lived access tokens combined with secure refresh tokens.",
            "cwe": "CWE-613",
            "owasp": "A07:2025-Authentication Failures",
        },
        # 3. Algorithm Confusion: public key used without algorithm specification
        {
            "id": "JWT-ALG-CONFUSION",
            "name": "Potential JWT Algorithm Confusion (Public Key as HMAC Secret)",
            "severity": Severity.HIGH,
            "cvss": 8.2,
            "regex": re.compile(
                r"""(?:jwt\.verify\s*\([^,]+,\s*(?:publicKey|pub_key|public_key|cert)\s*(?:\)|,\s*\{\s*\}|\))|jwt\.decode\s*\([^,]+,\s*(?:publicKey|pub_key|public_key|cert)\s*(?:\)|,\s*(?:verify=True)?\)))"""
            ),
            "description": "JWT verified against public key material without pinning the algorithm to asymmetric schemes (RS256/ES256). Attackers can sign tokens using the public key as an HMAC secret.",
            "remediation": "Always pass an explicit algorithm whitelist (e.g. algorithms=['RS256'] or { algorithms: ['RS256'] }) to verification calls.",
            "cwe": "CWE-327",
            "owasp": "A07:2025-Authentication Failures",
        },
    ]

    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir)
        self.matcher = IgnoreMatcher(self.target_dir)
        self.scanned_files_count: int = 0

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
                if self.matcher.is_ignored(fpath, is_dir=False):
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

            # 1. Regex pattern evaluations
            for pattern in self.PATTERNS:
                if pattern["regex"].search(line):
                    findings.append(
                        Finding(
                            title=pattern["name"],
                            category=Category.JWT.value,
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

            # 2. Weak dictionary HMAC secret detection
            m_sign = re.search(r"""(?:jwt\.sign|jwt\.encode|jwt\.verify|jwt\.decode)\s*\([^,]+,\s*['"]([a-zA-Z0-9_\-\.\$#@!%*]+)['"]""", line)
            if m_sign:
                secret_cand = m_sign.group(1).lower()
                if secret_cand in self.WEAK_HMAC_SECRETS:
                    findings.append(
                        Finding(
                            title=f"Weak Hardcoded JWT Secret ('{secret_cand}')",
                            category=Category.JWT.value,
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            description=(
                                f"Application uses weak dictionary string '{secret_cand}' as JWT HMAC secret. "
                                "Attackers can brute-force this secret offline and forge valid administrative tokens."
                            ),
                            evidence=f"{relpath}:{idx}\n> {stripped[:150]}",
                            remediation="Generate a cryptographically secure random secret (32+ bytes) and load it from environment variables.",
                            location=f"{relpath}:{idx}",
                            cwe_id="CWE-798",
                            owasp_category="A07:2025-Authentication Failures",
                        )
                    )

        return findings
