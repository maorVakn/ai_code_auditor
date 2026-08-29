"""
Wrapper for running Semgrep and normalizing its output into the tool's
unified finding format. Semgrep is multi-language (JS/TS, Go, Java, C/C++,
Ruby, PHP, and more) - its "auto" config pulls community rules appropriate
for whatever languages are actually present in the files it's given, with
no per-language setup needed on our side.

By convention (see aggregator.py), this is only ever called with non-Python
files - bandit already owns Python exclusively, so there's no overlap or
duplicate findings between the two tools for the same file.
"""
from __future__ import annotations

import json
import os
import subprocess

_SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}



def run_semgrep(target_paths: str | list[str]) -> list[dict]:
    """
    Runs semgrep on one or more paths (files and/or directories) and
    returns a normalized list of findings.

    Accepts either a single path (str) or a list of specific file paths -
    the latter is used by the aggregator to scan only files that changed
    since the last run (see cache.py).
    """
    if isinstance(target_paths, str):
        target_paths = [target_paths]

    if not target_paths:
        return []

    result = subprocess.run(
        ["semgrep", "--config", "auto", "--json", "--quiet", *target_paths],
        capture_output=True,
        text=True,
    )

    # Like bandit, semgrep can return a non-zero exit code when it finds
    # issues or hits per-file parse errors - that's expected, not a reason
    # to give up, as long as we got JSON back on stdout.
    if not result.stdout:
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings = []
    for issue in data.get("results", []):
        extra = issue.get("extra", {})
        metadata = extra.get("metadata", {})
        severity = _SEVERITY_MAP.get(extra.get("severity"), "UNRATED")
        cwe = metadata.get("cwe")
        references = metadata.get("references")
        findings.append({
            "source_tool": "semgrep",
            "category": "code_vulnerability",
            "rule_id": issue.get("check_id"),
            "rule_name": metadata.get("shortlink") or issue.get("check_id"),
            "file": os.path.normpath(issue["path"]),
            "line": issue.get("start", {}).get("line"),
            "severity": severity,
            "confidence": "MEDIUM",
            "raw_description": extra.get("message"),
            "code_snippet": extra.get("lines"),
            "cwe": cwe[0] if isinstance(cwe, list) and cwe else None,
            "more_info_url": references[0] if isinstance(references, list) and references else None,
        })

    return findings

if __name__ == "__main__":
    import sys
    findings = run_semgrep(sys.argv[1] if len(sys.argv) > 1 else ".")
    print(json.dumps(findings, indent=2, ensure_ascii=False))