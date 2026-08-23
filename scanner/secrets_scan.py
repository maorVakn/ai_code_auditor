"""
Wrapper for running detect-secrets and normalizing its output into the
tool's unified finding format.
detect-secrets catches both known patterns (AWS key, GitHub token, etc.)
and high-entropy strings that look like secrets even without a keyword.
"""
from __future__ import annotations

import json
import subprocess


def run_secrets_scan(target_paths: str | list[str]) -> list[dict]:
    """
    Accepts either a single path (str) or a list of specific file
    paths - the latter is used by the aggregator to scan only files
    that changed since the last run (see cache.py).
    """
    if isinstance(target_paths, str):
        target_paths = [target_paths]

    if not target_paths:
        return []

    result = subprocess.run(
        # --all-files: critical! without it, detect-secrets skips files
        # that start with a dot (.env, .env.local, etc.) and relies on
        # git tracking alone
        ["detect-secrets", "scan", *target_paths, "--all-files"],
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
    for filename, secrets in data.get("results", {}).items():
        for secret in secrets:
            findings.append({
                "source_tool": "detect-secrets",
                "category": "exposed_secret",
                "rule_id": secret["type"].replace(" ", "_").lower(),
                "rule_name": secret["type"],
                "file": filename,
                "line": secret["line_number"],
                # detect-secrets doesn't rate severity - an exposed
                # secret is almost always critical
                "severity": "HIGH",
                "confidence": "HIGH" if secret.get("is_verified") else "MEDIUM",
                "raw_description": f"Possible secret found of type '{secret['type']}'",
                "code_snippet": None,  # never store the actual secret value!
                "cwe": 798,  # CWE-798: Use of Hard-coded Credentials
                "more_info_url": "https://cwe.mitre.org/data/definitions/798.html",
            })

    return findings


if __name__ == "__main__":
    import sys
    findings = run_secrets_scan(sys.argv[1] if len(sys.argv) > 1 else ".")
    print(json.dumps(findings, indent=2, ensure_ascii=False))