"""
Wrapper for running bandit and normalizing its output into the tool's
unified finding format.
"""
import json
import subprocess


def run_bandit(target_path: str) -> list[dict]:
    """
    Runs bandit on a given path (file or directory) and returns a
    normalized list of findings. Each finding is normalized to a common
    structure so it can be merged with findings from other tools.
    """
    result = subprocess.run(
        ["bandit", "-r", "-f", "json", target_path],
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
            "file": issue["filename"],
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
