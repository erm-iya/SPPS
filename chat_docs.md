# SPPS Project Memory (SecAudit 2.0 Enterprise)

## 2026-11-25: Core Methodology Flaws Remediation (SecAudit Enterprise)
- **Decision / Change**: Implemented two-phase concurrent hydration and lockfile precedence in `sca_scanner.py`, assignment-only + guard exemption rules for prototype pollution, static markup exemption for `innerHTML`, lookback confinement checks for path traversal in `sast_scanner.py`, and smooth asymptotic ceiling $100 - 30(1 - e^{-0.06 H})$ in `models.py`.
- **to_do**: Prepare remote branch / pull request for repository collaboration.
- **to_remember**: Lockfiles (`package-lock.json`, `poetry.lock`, `composer.lock`, `Cargo.lock`) take absolute precedence over manifests in the same directory to avoid duplicate and inaccurate SCA counting.

## 2026-11-25: Comprehensive Methodology Critique & SecAudit 3.0 Roadmap
- **Decision / Change**: Authored complete architectural and algorithmic critique document `METHODOLOGY_CRITIQUE_AND_ROADMAP.md` analyzing 6 critical methodology flaws discovered during enterprise-scale audits: OSV batch severity truncation bug in `sca_scanner.py`, naive prototype pollution regex penalizing defensive blocklists in `sast_scanner.py`, blanket innerHTML false positives without taint tracking, lockfile/manifest dual-counting, and rigid mathematical ceiling traps in `models.py`.
- **to_do**: Fully executed remediation plan; all 23 unit tests passing.
- **to_remember**: OSV `/v1/querybatch` returns only `id` and `modified`, omitting `database_specific` severity metadata; never default batch findings to `Severity.HIGH`.

## 2026-11-23: Platform Modernization, Bug Hunting & Strix Integration
- **Decision / Change**: Refactored SecAudit 2.0 with OSV.dev batch API, cryptography-based DER SSL extraction, SPA catch-all filtering, K8s IaC auditing, Git diff-scoped scanning, OpenAPI/Swagger scanner, and automated OWASP Top 10:2025 + PoC curl generation.
- **to_do**: Await user confirmation before running live DAST or source audits against production targets.
- **to_remember**:
  - Always maintain Windows path safety when exporting SARIF (`location.rsplit(":", 1)`).
  - Never execute against live URLs without explicit user authorization.
  - In-code comments must remain 100% developer English (no Persian in source code).

## 2026-11-23: PyQt6 Modern Desktop GUI Studio
- **Decision / Change**: Implemented PyQt6 desktop interface (`gui.py` and `sec_audit/gui.py`) inspired by FoxLoader (Fluent dark styling) and UroStudio Pro (non-blocking QThread worker, QFileDialog directory browse, interactive findings table, and PoC curl clipboard copy).
- **to_do**: Test live GUI launch when user requests it.
- **to_remember**:
  - Execute audit orchestration strictly inside `QThread` to prevent UI freezing during parallel network/disk scans.

## 2026-11-23: Volume-Weighted & CVSS-Specific Scoring Engine Redesign
- **Decision / Change**: Overhauled scoring engine to calculate per-finding CVSS and exploitability multipliers ($E_i$), normalized by project volume metrics (KLoC, file count, package count, endpoints). Introduced 4 sub-pillars (SAST, SCA, IaC, DAST) and critical risk ceilings (guardrails).
- **to_do**: Await user confirmation before running live DAST or source audits against production targets.
- **to_remember**:
  - Always enforce critical severity ceilings (e.g. 1 Critical caps score at <= 69 / Grade C) regardless of codebase size.

## 2026-11-23: False Positive Elimination & Clustered Defect Density Scoring
- **Decision / Change**: Excluded third-party vendor directories (`libs/`, `vendor/`, `bower_components/`) and minified/bundled files (`*.min.*`, `*tailwindcss*`, `*jquery*`, `*.umd.*`). Introduced rule clustering cap (`MAX_FINDINGS_PER_RULE_PER_FILE = 5`), context-aware SSRF/SQLi filtering for client-side assets, and package-level deduplicated SCA scoring.
- **to_do**: Run benchmarks across multiple projects.
- **to_remember**:
  - SSRF and SQL string concatenation checks are strictly backend; never flag them against client-side browser files.
