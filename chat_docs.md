# SPPS Project Memory (SecAudit 2.0 Enterprise)

## 2026-11-23: Platform Modernization, Bug Hunting & Strix Integration
- **Decision / Change**: Refactored SecAudit 2.0 with OSV.dev batch API, cryptography-based DER SSL extraction, SPA catch-all filtering, K8s IaC auditing, Git diff-scoped scanning, OpenAPI/Swagger scanner, and automated OWASP Top 10:2025 + PoC curl generation.
- **to_do**: Await user confirmation before running live DAST or source audits against production targets.
- **to_remember**:
  - Always maintain Windows path safety when exporting SARIF (`location.rsplit(":", 1)`).
  - Never execute against live URLs without explicit user authorization.
  - In-code comments must remain 100% developer English (no Persian in source code).
