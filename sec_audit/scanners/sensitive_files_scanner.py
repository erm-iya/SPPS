import requests
from urllib.parse import urljoin
from typing import List
from ..models import Finding, Severity, Category
from ..config import SENSITIVE_PATHS, DEFAULT_TIMEOUT, DEFAULT_USER_AGENT


import uuid
import hashlib
import requests
from urllib.parse import urljoin
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor
from ..models import Finding, Severity, Category
from ..config import SENSITIVE_PATHS, DEFAULT_TIMEOUT, DEFAULT_USER_AGENT


class SensitiveFilesScanner:
    """
    Safely probes for exposed configuration files, git metadata, and diagnostic endpoints.
    Features concurrent path scanning and intelligent Single Page Application (SPA) catch-all detection.
    """

    def __init__(self, target_url: str, timeout: int = DEFAULT_TIMEOUT):
        self.target_url = target_url.rstrip("/") + "/"
        self.timeout = timeout
        self.headers = {"User-Agent": DEFAULT_USER_AGENT}
        self.is_spa_catchall = False
        self.catchall_signature = ""

    def _detect_spa_catchall(self, session: requests.Session) -> None:
        """
        Detects if target server returns HTTP 200 with generic HTML for non-existent paths.
        """
        random_suffix = f"probe_check_{uuid.uuid4().hex[:12]}.html"
        probe_url = urljoin(self.target_url, random_suffix)
        try:
            resp = session.get(
                probe_url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False,  # nosec: defensive auditor scanning targets with custom/self-signed certs
                allow_redirects=False,
            )
            if resp.status_code == 200:
                content = resp.text.strip()
                if "<!doctype html" in content.lower() or "<html" in content.lower():
                    self.is_spa_catchall = True
                    self.catchall_signature = hashlib.sha256(content[:2000].encode("utf-8", errors="ignore")).hexdigest()
        except Exception:
            pass

    def _probe_path(self, session: requests.Session, item: Dict[str, Any]) -> Optional[Finding]:
        rel_path = item["path"].lstrip("/")
        test_url = urljoin(self.target_url, rel_path)

        try:
            resp = session.get(
                test_url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False,  # nosec: defensive auditor scanning targets with custom/self-signed certs
                allow_redirects=False,
            )

            if resp.status_code == 200:
                content = resp.text
                content_lower = content.lower()
                content_type = resp.headers.get("Content-Type", "").lower()

                # Special handling for robots.txt
                if rel_path == "robots.txt":
                    disallows = [line.strip() for line in content.splitlines() if line.lower().startswith("disallow:")]
                    if disallows:
                        return Finding(
                            title="Robots.txt Discloses Hidden Paths",
                            category=Category.EXPOSED_FILES.value,
                            severity=Severity.INFO,
                            description=f"robots.txt reveals {len(disallows)} disallowed paths which may provide directory intelligence to attackers.",
                            evidence="\n".join(disallows[:10]) + ("\n..." if len(disallows) > 10 else ""),
                            remediation="Ensure sensitive directories listed in robots.txt have proper authentication and authorization controls.",
                            location=test_url,
                            cwe_id="CWE-200",
                        )
                    return None

                # If server is an SPA catch-all, verify against generic catchall signature
                if self.is_spa_catchall:
                    probe_sig = hashlib.sha256(content[:2000].encode("utf-8", errors="ignore")).hexdigest()
                    if probe_sig == self.catchall_signature:
                        return None
                    # Non-HTML endpoints should never return standard HTML on valid findings
                    non_html_targets = [".env", ".git", ".log", ".yml", ".yaml", ".json", ".bak"]
                    if any(target in rel_path for target in non_html_targets) and ("<!doctype html" in content_lower or "<html" in content_lower):
                        return None

                # Verify keyword signature match
                matches_keyword = any(kw.lower() in content_lower for kw in item["keywords"])
                if matches_keyword:
                    # Generic HTML page rejection for configuration and secret files
                    if any(rel_path.endswith(ext) for ext in [".env", ".bak", ".log", ".yml"]) and "<!doctype html" in content_lower:
                        return None

                    snippet = content[:300].strip()
                    return Finding(
                        title=f"Exposed Sensitive File: {item['name']}",
                        category=Category.EXPOSED_FILES.value,
                        severity=Severity(item["severity"]),
                        description=f"Publicly accessible sensitive file found at {test_url}. This can lead to complete server compromise or data breach.",
                        evidence=f"HTTP 200 OK\nSnippet:\n{snippet}",
                        remediation=f"Immediately delete or restrict web access to '{item['path']}' in your web server configuration (Nginx, Apache, etc.).",
                        location=test_url,
                        cwe_id="CWE-552",
                        reference="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                        poc_curl=f'curl -i -s "{test_url}"',
                        owasp_category="A01:2025-Broken Access Control & SSRF",
                    )
        except requests.exceptions.RequestException:
            pass

        return None

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        with requests.Session() as session:
            # Detect SPA catch-all behavior
            self._detect_spa_catchall(session)

            # Concurrent probing across sensitive paths
            with ThreadPoolExecutor(max_workers=min(len(SENSITIVE_PATHS), 8)) as executor:
                futures = [executor.submit(self._probe_path, session, item) for item in SENSITIVE_PATHS]
                for f in futures:
                    try:
                        res = f.result()
                        if res:
                            findings.append(res)
                    except Exception:
                        pass

        return findings
