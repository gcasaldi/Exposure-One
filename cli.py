"""CLI runner for Exposure One scans (terminal-only)"""
import argparse
import json
import sys
from app.core.scanner import Scanner


def format_table(result: dict) -> str:
    risk = result.get("risk_score", {})
    exec_view = result.get("executive_view", {})
    modules = result.get("technical_view", {}).get("modules_results", [])

    lines = []
    lines.append("=== Exposure One (CLI) ===")
    lines.append(f"Target        : {result.get('target')}")
    lines.append(f"Scan ID       : {result.get('scan_id')}")
    lines.append(f"Timestamp     : {result.get('timestamp')}")
    lines.append(f"Exposure Score: {risk.get('total_score')} ({risk.get('risk_level')})")
    lines.append("Top Risks     :")
    for r in exec_view.get("top_risks", []) or ["N/A"]:
        lines.append(f"  - {r}")
    lines.append("Recommendations:")
    for rec in exec_view.get("recommendations", []) or ["N/A"]:
        lines.append(f"  - {rec}")
    lines.append("Modules:")
    for module in modules:
        m_findings = module.get('findings', [])
        lines.append(f"  * {module.get('module_name')} (status={module.get('status')}, findings={len(m_findings)})")
        for f in m_findings:
            title = f.get('title', 'n/a')
            lines.append(f"      - {title}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Run Exposure One scan from terminal")
    parser.add_argument("--target", help="Domain or IP to scan")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    args = parser.parse_args()

    target = args.target
    if not target:
        target = input("Inserisci dominio o IP: ").strip()
        if not target:
            sys.stderr.write("Nessun target fornito.\n")
            sys.exit(1)
    confirm = input(f"Scansiono '{target}'? [y/N]: ").strip().lower()
    if confirm not in {"y", "yes"}:
        print("Annullato.")
        return

    scanner = Scanner()
    try:
        result = scanner.scan(target)
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)

    if args.format == "json":
        print(json.dumps(result.model_dump(), indent=2))
    else:
        print(format_table(result.model_dump()))


if __name__ == "__main__":
    main()
