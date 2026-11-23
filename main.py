#!/usr/bin/env python3
"""
SecAudit 2.0 Enterprise - Comprehensive Security & Compliance Auditing Platform
CLI Entry Point
"""

import os
import sys
import argparse
import webbrowser
from pathlib import Path
import urllib3

# Suppress unverified HTTPS request warnings from polluting terminal output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ensure UTF-8 output on Windows console
if sys.platform == "win32":
    if sys.stdout.encoding != "utf-8":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

from sec_audit.orchestrator import SecAuditOrchestrator
from sec_audit.reporting import TerminalReporter, JSONReporter, HTMLReporter, SARIFReporter, MarkdownReporter


def parse_args():
    parser = argparse.ArgumentParser(
        description="SecAudit 2.0 Enterprise - Comprehensive Security, Secret & Dependency Auditing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a live website (DAST, SSL, DNS, CSP, Tech Stack, Exposed Files)
  python main.py --url https://example.com

  # Scan source code, secrets, Docker, and dependencies in a project
  python main.py --dir /path/to/project

  # Full enterprise audit with interactive HTML, JSON, and SARIF exports
  python main.py --url https://example.com --dir . --html report.html --json report.json --sarif report.sarif
        """,
    )

    parser.add_argument(
        "-u", "--url",
        help="Target website URL to scan (e.g. https://example.com or http://localhost:3000)",
        type=str,
        default=None,
    )
    parser.add_argument(
        "-d", "--dir",
        help="Target source code directory for SAST, IaC, SCA and License scans",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--html",
        help="Path to generate interactive HTML report (default: report.html)",
        type=str,
        default="report.html",
    )
    parser.add_argument(
        "--json",
        help="Path to export JSON report (e.g. report.json)",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--sarif",
        help="Path to export OASIS SARIF v2.1.0 report for GitHub Actions / GitLab CI/CD (e.g. results.sarif)",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--md",
        help="Path to export comprehensive Markdown audit report (e.g. audit.md)",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--diff",
        help="Audit only changed or staged files in the current Git working tree",
        action="store_true",
    )
    parser.add_argument(
        "--diff-base",
        help="Git base reference for diff comparison (e.g. main, HEAD~1)",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--no-browser",
        help="Do not automatically open HTML report in the default browser",
        action="store_true",
    )
    parser.add_argument(
        "--offline",
        help="Run in offline mode without querying online vulnerability databases (OSV.dev)",
        action="store_true",
    )
    parser.add_argument(
        "--timeout",
        help="HTTP request timeout in seconds (default: 10)",
        type=int,
        default=10,
    )
    parser.add_argument(
        "--threads",
        help="Number of concurrent worker threads (default: 6)",
        type=int,
        default=6,
    )
    parser.add_argument(
        "--fail-on",
        help="Exit with code 2 if vulnerabilities at or above this severity are detected (e.g. CRITICAL, HIGH, MEDIUM, LOW)",
        type=str,
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=None,
    )

    return parser.parse_args()


def interactive_prompt():
    print("=" * 65)
    print("      🔒 SecAudit 2.0 Enterprise - Security & Compliance Auditor")
    print("=" * 65)
    print("1) Scan Live Website (DAST, SSL, DNS, CSP, Tech Stack, Headers)")
    print("2) Scan Source Code, Secrets, Docker & Packages (SAST, IaC, SCA)")
    print("3) Full Enterprise Audit (Both Live Website & Source Code)")
    print("4) Exit")
    print("-" * 65)

    choice = input("Select an option [1-4]: ").strip()

    target_url = None
    target_dir = None

    if choice == "1":
        target_url = input("Enter website URL (e.g. https://example.com): ").strip()
    elif choice == "2":
        target_dir = input("Enter project directory path [default .]: ").strip() or "."
    elif choice == "3":
        target_url = input("Enter website URL (e.g. https://example.com): ").strip()
        target_dir = input("Enter project directory path [default .]: ").strip() or "."
    else:
        print("Exiting.")
        sys.exit(0)

    return target_url, target_dir


def main():
    args = parse_args()

    target_url = args.url
    target_dir = args.dir

    if not target_url and not target_dir:
        if len(sys.argv) == 1:
            target_url, target_dir = interactive_prompt()
        else:
            print("[!] Please specify at least --url or --dir. Run with --help for details.")
            sys.exit(1)

    # Normalize target URL if protocol scheme is missing
    if target_url:
        target_url = target_url.strip()
        if not (target_url.startswith("http://") or target_url.startswith("https://")):
            target_url = "https://" + target_url

    print(f"\n[*] Initializing SecAudit 2.0 Enterprise Engine...")
    if target_url:
        print(f"    - Target URL:       {target_url}")
    if target_dir:
        print(f"    - Target Directory: {os.path.abspath(target_dir)}")

    orchestrator = SecAuditOrchestrator(
        target_url=target_url,
        target_dir=target_dir,
        check_online_sca=not args.offline,
        timeout=args.timeout,
        max_workers=args.threads,
        diff_mode=args.diff,
        diff_base=args.diff_base,
    )

    result = orchestrator.run()

    # 1. Terminal Output
    terminal_rep = TerminalReporter(result)
    terminal_rep.display()

    # 2. JSON Output
    if args.json:
        json_rep = JSONReporter(result)
        json_rep.export(args.json)
        print(f"[+] JSON report saved to: {os.path.abspath(args.json)}")

    # 3. SARIF Output
    if args.sarif:
        sarif_rep = SARIFReporter(result)
        sarif_rep.export(args.sarif)
        print(f"[+] SARIF report saved to: {os.path.abspath(args.sarif)}")

    # 4. HTML Output
    if args.html:
        html_rep = HTMLReporter(result)
        html_rep.export(args.html)
        html_path = os.path.abspath(args.html)
        print(f"[+] Interactive HTML dashboard saved to: {html_path}")

        if not args.no_browser:
            try:
                webbrowser.open(Path(html_path).as_uri())
            except Exception:
                pass

    # 5. Markdown Output
    if args.md:
        md_rep = MarkdownReporter(result)
        md_rep.export(args.md)
        print(f"[+] Markdown security audit report saved to: {os.path.abspath(args.md)}")

    # 6. CI/CD Pipeline Quality Gate Check
    if args.fail_on:
        threshold_rank = SecAuditOrchestrator.SEVERITY_ORDER.get(args.fail_on.upper(), 99)
        highest_found_rank = 99
        for f in result.findings:
            f_rank = SecAuditOrchestrator.SEVERITY_ORDER.get(f.severity.value, 99)
            if f_rank < highest_found_rank:
                highest_found_rank = f_rank

        if highest_found_rank <= threshold_rank:
            print(f"\n[!] CI/CD Gate Failed: Vulnerabilities meeting or exceeding '{args.fail_on.upper()}' severity were found!")
            sys.exit(2)


if __name__ == "__main__":
    main()
