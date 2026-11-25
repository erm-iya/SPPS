"""
Infrastructure as Code (IaC) Security Auditor for Docker, Docker Compose, and Kubernetes
"""

import os
import re
from typing import List
from ..models import Finding, Severity, Category
from ..config import IGNORE_DIRS
from ..ignore_matcher import IgnoreMatcher


class IaCScanner:
    """
    Audits Dockerfiles, Docker Compose files, and Kubernetes manifests for security misconfigurations.
    """

    EXPOSED_DB_PORTS = {
        "27017": "MongoDB",
        "3306": "MySQL/MariaDB",
        "5432": "PostgreSQL",
        "6379": "Redis",
        "9200": "Elasticsearch",
        "1521": "Oracle DB",
        "1433": "MS SQL Server",
    }

    K8S_KINDS = {
        "deployment", "pod", "daemonset", "statefulset", "job", "cronjob", "replicaset"
    }

    def __init__(self, target_dir: str):
        self.target_dir = os.path.abspath(target_dir)
        self.matcher = IgnoreMatcher(self.target_dir)
        self.manifests_count: int = 0

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        if not os.path.exists(self.target_dir):
            return findings

        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [
                d for d in dirs 
                if not self.matcher.is_ignored(os.path.join(root, d), is_dir=True)
            ]

            for file in files:
                filepath = os.path.join(root, file)
                if self.matcher.is_ignored(filepath, is_dir=False):
                    continue
                relpath = os.path.relpath(filepath, self.target_dir)
                filename_lower = file.lower()

                # 1. Audit Dockerfile
                if filename_lower == "dockerfile" or filename_lower.endswith(".dockerfile"):
                    self.manifests_count += 1
                    findings.extend(self._audit_dockerfile(filepath, relpath))

                # 2. Audit Docker Compose
                elif filename_lower in ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]:
                    self.manifests_count += 1
                    findings.extend(self._audit_docker_compose(filepath, relpath))

                # 3. Audit Kubernetes Manifests
                elif filename_lower.endswith((".yaml", ".yml")):
                    self.manifests_count += 1
                    findings.extend(self._audit_k8s_manifest(filepath, relpath))

                # 4. Audit Terraform Infrastructure as Code
                elif filename_lower.endswith((".tf", ".tfvars")):
                    self.manifests_count += 1
                    findings.extend(self._audit_terraform(filepath, relpath))

        return findings

    def _audit_dockerfile(self, manifest_file: str, relpath: str) -> List[Finding]:
        findings = []
        try:
            with open(manifest_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return findings

        has_user_directive = False

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            # Check unpinned/latest base image (excluding scratch)
            if re.match(r"^FROM\s+[a-zA-Z0-9_\-\.\/]+:latest", stripped, re.IGNORECASE) or (
                stripped.startswith("FROM ") and ":" not in stripped and "AS" not in stripped and not stripped.strip().lower().endswith("scratch")
            ):
                findings.append(
                    Finding(
                        title="Dockerfile Uses Unpinned ':latest' Base Image",
                        category=Category.IAC.value,
                        severity=Severity.LOW,
                        cvss_score=3.5,
                        description="Using the ':latest' tag or omitting image version tags leads to non-reproducible builds and automatic ingestion of breaking/vulnerable upstream changes.",
                        evidence=f"{relpath}:{idx}\n> {stripped}",
                        remediation="Pin the base image to a specific SHA digest or stable semantic version tag (e.g. node:20-alpine or python:3.12-slim).",
                        location=f"{relpath}:{idx}",
                        cwe_id="CWE-1188",
                        owasp_category="A03:2025-Software Supply Chain Failures",
                    )
                )

            # Check hardcoded secrets in ENV
            if re.match(r"^ENV\s+(?:.*(?:PASSWORD|SECRET|API_KEY|TOKEN|AUTH_KEY))\s*=", stripped, re.IGNORECASE):
                findings.append(
                    Finding(
                        title="Hardcoded Secret in Dockerfile ENV Instruction",
                        category=Category.IAC.value,
                        severity=Severity.HIGH,
                        cvss_score=7.8,
                        description="Environment variables defined via ENV in a Dockerfile persist in image layers and can be extracted using 'docker inspect' or 'docker history'.",
                        evidence=f"{relpath}:{idx}\n> {stripped}",
                        remediation="Do not bake secrets into images. Inject secrets at runtime using environment files or secrets managers.",
                        location=f"{relpath}:{idx}",
                        cwe_id="CWE-798",
                        owasp_category="A04:2025-Cryptographic Failures",
                    )
                )

            # Check USER directive
            if stripped.startswith("USER "):
                has_user_directive = True

        if not has_user_directive and len(lines) > 2:
            findings.append(
                Finding(
                    title="Dockerfile Missing Non-Root USER Directive",
                    category=Category.IAC.value,
                    severity=Severity.MEDIUM,
                    cvss_score=6.0,
                    description="The container runs as 'root' by default. If the application is compromised, the attacker gains root privileges inside the container.",
                    remediation="Create and switch to a dedicated non-root user (e.g. 'USER appuser' or 'USER node') before CMD/ENTRYPOINT.",
                    location=relpath,
                    cwe_id="CWE-250",
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
                    owasp_category="A02:2025-Security Misconfiguration",
                )
            )

        return findings

    def _audit_docker_compose(self, manifest_file: str, relpath: str) -> List[Finding]:
        findings = []
        try:
            with open(manifest_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            return findings

        # Check privileged mode
        if "privileged: true" in content:
            findings.append(
                Finding(
                    title="Container Runs in Privileged Mode (privileged: true)",
                    category=Category.IAC.value,
                    severity=Severity.CRITICAL,
                    cvss_score=9.1,
                    description="Running a container with 'privileged: true' gives it full root capabilities on the host system, allowing easy container breakout.",
                    evidence=f"privileged: true in {relpath}",
                    remediation="Remove 'privileged: true' and grant only specific required Linux capabilities (cap_add).",
                    location=relpath,
                    cwe_id="CWE-250",
                    owasp_category="A02:2025-Security Misconfiguration",
                )
            )

        # Check directly exposed database ports
        for port, db_name in self.EXPOSED_DB_PORTS.items():
            pattern = re.compile(rf"""['"]?{port}:{port}['"]?""")
            for idx, line in enumerate(lines, start=1):
                if pattern.search(line) and not "127.0.0.1" in line:
                    findings.append(
                        Finding(
                            title=f"Database Port ({port}/{db_name}) Directly Exposed to 0.0.0.0",
                            category=Category.IAC.value,
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            description=f"{db_name} port {port} is exposed on all network interfaces. Attackers on the local network or internet can reach database endpoints directly.",
                            evidence=f"{relpath}:{idx}\n> {line.strip()}",
                            remediation=f"Bind port to localhost only ('127.0.0.1:{port}:{port}') or use internal Docker network without host port mapping.",
                            location=f"{relpath}:{idx}",
                            cwe_id="CWE-668",
                            poc_curl=f'curl -v "telnet://target-ip:{port}"',
                            owasp_category="A01:2025-Broken Access Control & SSRF",
                        )
                    )

        return findings

    def _audit_k8s_manifest(self, manifest_file: str, relpath: str) -> List[Finding]:
        findings = []
        try:
            with open(manifest_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return findings

        if "apiVersion:" not in content or "kind:" not in content:
            return findings

        kind_match = re.search(r"^\s*kind:\s*([a-zA-Z0-9]+)", content, re.MULTILINE)
        if not kind_match or kind_match.group(1).lower() not in self.K8S_KINDS:
            return findings

        k8s_kind = kind_match.group(1)

        # 1. Check privileged container execution
        if re.search(r"privileged:\s*true", content, re.IGNORECASE):
            findings.append(
                Finding(
                    title=f"Kubernetes {k8s_kind} Container Runs with Privileged Access",
                    category=Category.IAC.value,
                    severity=Severity.CRITICAL,
                    cvss_score=9.0,
                    description=f"Manifest '{relpath}' configures 'privileged: true', granting container processes root access to host node capabilities.",
                    evidence=f"privileged: true in {relpath}",
                    remediation="Disable privileged container mode and grant only required Linux capabilities via cap_add/cap_drop.",
                    location=relpath,
                    cwe_id="CWE-250",
                    owasp_category="A02:2025-Security Misconfiguration",
                )
            )

        # 2. Check allowPrivilegeEscalation
        if re.search(r"allowPrivilegeEscalation:\s*true", content, re.IGNORECASE):
            findings.append(
                Finding(
                    title=f"Kubernetes {k8s_kind} Allows Privilege Escalation",
                    category=Category.IAC.value,
                    severity=Severity.HIGH,
                    cvss_score=7.8,
                    description=f"Manifest '{relpath}' permits child processes to gain more privileges than their parent process.",
                    evidence=f"allowPrivilegeEscalation: true in {relpath}",
                    remediation="Set 'securityContext.allowPrivilegeEscalation: false' on container specifications.",
                    location=relpath,
                    cwe_id="CWE-250",
                    owasp_category="A02:2025-Security Misconfiguration",
                )
            )

        # 3. Check dangerous hostPath mounts
        hostpath_matches = re.findall(r"hostPath:\s*\n\s*path:\s*([^\s]+)", content, re.IGNORECASE)
        for hpath in hostpath_matches:
            clean_hp = hpath.strip("'\"")
            if clean_hp in ["/", "/etc", "/var/run/docker.sock", "/run/containerd/containerd.sock", "/root"]:
                findings.append(
                    Finding(
                        title=f"Kubernetes {k8s_kind} Mounts Sensitive Host Path ({clean_hp})",
                        category=Category.IAC.value,
                        severity=Severity.CRITICAL,
                        cvss_score=9.3,
                        description=f"Mounting sensitive host path '{clean_hp}' allows container processes to escape and compromise the host node.",
                        evidence=f"hostPath.path: {clean_hp} in {relpath}",
                        remediation="Avoid mounting sensitive host paths into containers. Use PersistentVolumes or ConfigMaps instead.",
                        location=relpath,
                        cwe_id="CWE-668",
                        owasp_category="A01:2025-Broken Access Control & SSRF",
                    )
                )

        # 4. Check unpinned / latest images
        image_matches = re.findall(r"image:\s*([a-zA-Z0-9_\-\.\/\@\:]+)", content)
        for img in image_matches:
            if img.endswith(":latest") or (":" not in img and "@" not in img):
                findings.append(
                    Finding(
                        title=f"Kubernetes {k8s_kind} Uses Unpinned ':latest' Container Image",
                        category=Category.IAC.value,
                        severity=Severity.LOW,
                        cvss_score=3.5,
                        description=f"Container image '{img}' in {relpath} uses ':latest' or lacks an explicit version tag.",
                        evidence=f"image: {img} in {relpath}",
                        remediation="Pin container images to an immutable SHA256 digest or a specific semantic release tag.",
                        location=relpath,
                        cwe_id="CWE-1188",
                        owasp_category="A03:2025-Software Supply Chain Failures",
                    )
                )

        return findings

    def _audit_terraform(self, tf_file: str, relpath: str) -> List[Finding]:
        findings = []
        try:
            with open(tf_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            return findings

        # 1. Plaintext credentials in provider blocks
        if re.search(r"""provider\s+["']aws["']""", content):
            if re.search(r"""(?:access_key|secret_key)\s*=\s*["'][a-zA-Z0-9_\-\/+=]{10,}["']""", content):
                findings.append(
                    Finding(
                        title="Terraform AWS Provider Contains Hardcoded Credentials",
                        category=Category.IAC.value,
                        severity=Severity.CRITICAL,
                        cvss_score=9.0,
                        description=f"Hardcoded access_key or secret_key discovered in AWS provider block in {relpath}.",
                        evidence=f"File: {relpath}\nStatic AWS credentials configured in provider block.",
                        remediation="Remove hardcoded credentials. Use AWS IAM Roles, environment variables (AWS_ACCESS_KEY_ID), or Vault.",
                        location=relpath,
                        cwe_id="CWE-798",
                        owasp_category="A04:2025-Cryptographic Failures",
                    )
                )

        # 2. S3 bucket public access
        if re.search(r"""(?:acl\s*=\s*["']public-read(?:-write)?["']|block_public_acls\s*=\s*false|block_public_policy\s*=\s*false)""", content):
            findings.append(
                Finding(
                    title="Terraform S3 Bucket Configured with Public Read / Write Access",
                    category=Category.IAC.value,
                    severity=Severity.HIGH,
                    cvss_score=8.2,
                    description=f"S3 bucket in {relpath} enables public access (public-read ACL or disabled block_public_acls). Data may be exposed to the entire internet.",
                    evidence=f"File: {relpath}\nPublic ACL or disabled public block detected.",
                    remediation="Set acl = 'private' and enable all aws_s3_bucket_public_access_block settings.",
                    location=relpath,
                    cwe_id="CWE-732",
                    owasp_category="A01:2025-Broken Access Control & SSRF",
                )
            )

        # 3. Unrestricted ingress (0.0.0.0/0 on sensitive ports)
        has_wildcard_cidr = bool(re.search(r"""cidr_blocks\s*=\s*\[[^\]]*["']0\.0\.0\.0\/0["'][^\]]*\]""", content))
        if has_wildcard_cidr:
            # Check ports 22 (SSH), 3389 (RDP), or database ports
            sensitive_ports = ("22", "3389", "3306", "5432", "27017", "6379", "1433")
            for port in sensitive_ports:
                if re.search(rf"""(?:from_port|to_port)\s*=\s*{port}\b""", content):
                    service_name = "SSH (22)" if port == "22" else ("RDP (3389)" if port == "3389" else f"Database Port ({port})")
                    findings.append(
                        Finding(
                            title=f"Terraform Security Group Exposes {service_name} to 0.0.0.0/0",
                            category=Category.IAC.value,
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            description=f"Security group rule in {relpath} allows inbound traffic from entire internet (0.0.0.0/0) to {service_name}.",
                            evidence=f"File: {relpath}\nIngress rule exposes port {port} to 0.0.0.0/0",
                            remediation=f"Restrict ingress on port {port} to trusted VPN or internal CIDR blocks.",
                            location=relpath,
                            cwe_id="CWE-284",
                            owasp_category="A02:2025-Security Misconfiguration",
                        )
                    )
                    break

        # 4. Unencrypted storage (EBS / RDS / S3)
        if re.search(r"""resource\s+["'](?:aws_ebs_volume|aws_db_instance)["']""", content):
            if re.search(r"""(?:encrypted|storage_encrypted)\s*=\s*false""", content):
                findings.append(
                    Finding(
                        title="Terraform Storage Resource Has Encryption Disabled",
                        category=Category.IAC.value,
                        severity=Severity.MEDIUM,
                        cvss_score=5.5,
                        description=f"Storage volume/instance in {relpath} explicitly sets encrypted = false.",
                        evidence=f"File: {relpath}\nencrypted = false discovered.",
                        remediation="Enable KMS encryption by setting encrypted = true (or storage_encrypted = true).",
                        location=relpath,
                        cwe_id="CWE-311",
                        owasp_category="A04:2025-Cryptographic Failures",
                    )
                )

        return findings
