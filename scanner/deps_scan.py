"""
Wrapper for running pip-audit and normalizing its output into the
tool's unified finding format. Checks requirements.txt against the
osv.dev known-vulnerability database.
"""
from __future__ import annotations

import json
import subprocess


def run_deps_scan(requirements_path: str) -> list[dict]:
    result = subprocess.run(
        ["pip-audit", "-r", requirements_path, "-f", "json"],
        capture_output=True,
        text=True,
    )

    if not result.stdout:
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings = []
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            findings.append({
                "source_tool": "pip-audit",
                "category": "vulnerable_dependency",
                "rule_id": vuln["id"],
                "rule_name": f"{dep['name']} {dep['version']}",
                "file": requirements_path,
                "line": None,  # not applicable - this is a package-level issue, not a line
                # pip-audit doesn't return severity directly - we leave
                # it to the AI to rate based on the description
                "severity": "UNRATED",
                "confidence": "HIGH",  # verified CVE from an official database
                "raw_description": vuln.get("description", ""),
                "code_snippet": None,
                "cwe": None,
                "more_info_url": f"https://osv.dev/vulnerability/{vuln['id']}",
                "fix_versions": vuln.get("fix_versions", []),
                "aliases": vuln.get("aliases", []),  # equivalent CVE identifiers
            })

    return findings


if __name__ == "__main__":
    import sys
    findings = run_deps_scan(sys.argv[1] if len(sys.argv) > 1 else "requirements.txt")
    print(json.dumps(findings, indent=2, ensure_ascii=False))