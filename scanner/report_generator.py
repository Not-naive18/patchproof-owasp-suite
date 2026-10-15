#!/usr/bin/env python3
"""
PatchProof AI - Report & Verification Payload Generator
Formats scanner findings into Developer/Reviewer Portal formats and regression inputs.
"""

import json
import sys
from pathlib import Path

def generate_markdown_summary(findings):
    md = []
    md.append("# 🛡️ PatchProof AI Security Audit Report")
    md.append(f"**Total Findings Detected:** {len(findings)}\n")
    md.append("| # | Severity | OWASP Category | CWE | File Location | Line |")
    md.append("|---|---|---|---|---|---|")

    for idx, f in enumerate(findings, 1):
        sev_badge = "🔴 " if f["severity"] == "CRITICAL" else ("🟠 " if f["severity"] == "HIGH" else "🟡 ")
        rel_file = Path(f["file"]).name
        md.append(f"| {idx} | {sev_badge}{f['severity']} | {f['category']} | {f['cwe']} | `{rel_file}` | {f['line']} |")

    md.append("\n## Detailed Remediation Guidance\n")
    for idx, f in enumerate(findings, 1):
        md.append(f"### Finding {idx}: {f['category']} ({f['cwe']})")
        md.append(f"- **File:** `{f['file']}` (Line {f['line']})")
        md.append(f"- **Vulnerable Snippet:**\n```\n{f['code_snippet']}\n```")
        md.append(f"- **Advisory:** {f['message']}")
        md.append("- **Verification Action:** Re-run regression test suite after applying patch.")
        md.append("")

    return "\n".join(md)

def main():
    json_path = Path("scan-results.json")
    if not json_path.exists():
        print("[!] No scan-results.json found. Run scanner with --output scan-results.json first.")
        return

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = data.get("findings", [])
    report_md = generate_markdown_summary(findings)

    with open("SECURITY_AUDIT_REPORT.md", "w", encoding="utf-8") as out:
        out.write(report_md)

    print(f"[✓] SECURITY_AUDIT_REPORT.md successfully generated with {len(findings)} findings.")

if __name__ == "__main__":
    main()
