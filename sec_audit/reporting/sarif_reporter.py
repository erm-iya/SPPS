"""
OASIS SARIF (Static Analysis Results Interchange Format) v2.1.0 Reporter
Enables native integration with GitHub Code Scanning, GitLab Security Dashboards, and CI/CD pipelines.
"""

import os
import json
from typing import Dict, Any
from ..models import ScanResult, Severity


class SARIFReporter:
    """
    Exports scan findings to standard SARIF v2.1.0 format.
    """

    SEVERITY_LEVEL_MAP = {
        Severity.CRITICAL.value: "error",
        Severity.HIGH.value: "error",
        Severity.MEDIUM.value: "warning",
        Severity.LOW.value: "note",
        Severity.INFO.value: "note",
    }

    def __init__(self, result: ScanResult):
        self.result = result

    def export(self, filepath: str) -> None:
        rules = []
        rule_indices = {}
        results = []

        for f in self.result.findings:
            # Generate a distinct rule_id to prevent metadata collision between findings
            clean_title_slug = f.title.replace(" ", "_")
            rule_id = f"{f.cwe_id}_{clean_title_slug}" if f.cwe_id else clean_title_slug

            if rule_id not in rule_indices:
                rule_indices[rule_id] = len(rules)
                rule_entry = {
                    "id": rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "helpUri": f.reference or "https://owasp.org",
                    "help": {
                        "text": f"Remediation:\n{f.remediation}",
                        "markdown": f"**Remediation:**\n{f.remediation}",
                    },
                }
                if f.cwe_id:
                    rule_entry["properties"] = {"cwe": f.cwe_id}
                rules.append(rule_entry)

            rule_idx = rule_indices[rule_id]

            # Parse location (filepath:line), handling Windows drive letters (e.g. C:\path\file:10)
            file_uri = "index.html"
            line_num = 1
            if f.location:
                if ":" in f.location:
                    loc_path, loc_line = f.location.rsplit(":", 1)
                    if loc_line.isdigit():
                        file_uri = loc_path.replace("\\", "/")
                        line_num = max(1, int(loc_line))
                    else:
                        file_uri = f.location.replace("\\", "/")
                        line_num = 1
                else:
                    file_uri = f.location.replace("\\", "/")

            result_entry = {
                "ruleId": rule_id,
                "ruleIndex": rule_idx,
                "level": self.SEVERITY_LEVEL_MAP.get(f.severity.value, "warning"),
                "message": {"text": f"{f.title}: {f.description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": line_num,
                            },
                        }
                    }
                ],
                "properties": {
                    "closure_state": f.closure_state,
                    "cvss_score": f.cvss_score,
                },
            }
            if f.poc_curl:
                result_entry["properties"]["poc_curl"] = f.poc_curl
            if f.counterevidence:
                result_entry["properties"]["counterevidence"] = f.counterevidence
            results.append(result_entry)

        sarif_data: Dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecAudit",
                            "semanticVersion": "2.0.0",
                            "informationUri": "https://github.com/secaudit/secaudit",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

        target_path = os.path.abspath(filepath)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as out:
            json.dump(sarif_data, out, indent=2, ensure_ascii=False)
