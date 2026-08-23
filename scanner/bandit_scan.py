"""
Wrapper for running bandit and normalizing its output into the tool's
unified finding format.
"""
from __future__ import annotations

import json
import os
import subprocess


def run_bandit(target_paths: str | list[str]) -> list[dict]:
    """
    Runs bandit on one or more paths (files and/or directories) and
    returns a normalized list of findings.

    Accepts either a single path (str) or a list of specific file
    paths - the latter is used by the aggregator to scan only files
    that changed since the last run (see cache.py).
    """
    if isinstance(target_paths, str):
        target_paths = [target_paths]

    if not target_paths:
        return []

    result = subprocess.run(
        ["bandit", "-r", "-f", "json", *target_paths],
        capture_output=True,
        text=True,
    )

    # bandit returns a non-zero exit code when it finds issues -
    # that's expected behavior, not an error
    if not result.stdout:
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings = []
    for issue in data.get("results", []):
        findings.append({
            "source_tool": "bandit",
            "category": "code_vulnerability",
            "rule_id": issue["test_id"],
            "rule_name": issue["test_name"],
            # bandit prefixes filenames with "./" - normalize so this
            # matches the exact paths we pass in (important for the
            # cache in aggregator.py to correctly attribute findings
            # back to the file that produced them)
            "file": os.path.normpath(issue["filename"]),
            "line": issue["line_number"],
            "severity": issue["issue_severity"],       # LOW / MEDIUM / HIGH
            "confidence": issue["issue_confidence"],    # LOW / MEDIUM / HIGH
            "raw_description": issue["issue_text"],
            "code_snippet": issue["code"],
            "cwe": issue.get("issue_cwe", {}).get("id"),
            "more_info_url": issue.get("more_info"),
        })

    return findings


if __name__ == "__main__":
    import sys
    findings = run_bandit(sys.argv[1] if len(sys.argv) > 1 else ".")
    print(json.dumps(findings, indent=2, ensure_ascii=False))