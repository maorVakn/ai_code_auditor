"""
Small redaction helpers for report data.

Scanner tools sometimes echo the sensitive value they found. Reports and
caches should identify the location and rule without persisting the secret.
"""
from __future__ import annotations

import re
from copy import deepcopy


SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b[\w.-]*(?:api[_-]?key|token|secret|password|passwd|pwd|access[_-]?key)[\w.-]*\b\s*[:=]\s*)([\"']?)([^\"'\s,;]+)([\"']?)"
)
QUOTED_SECRET_RE = re.compile(r"(?i)(password|secret|token|api[_-]?key)[^:]*:\s*'([^']+)'")
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")


def redact_text(value: str | None) -> str | None:
    if value is None:
        return None

    redacted = AWS_KEY_RE.sub("[REDACTED_SECRET]", value)
    redacted = SECRET_ASSIGNMENT_RE.sub(r"\1\2[REDACTED_SECRET]\4", redacted)
    return QUOTED_SECRET_RE.sub(r"\1: '[REDACTED_SECRET]'", redacted)


def redact_finding(finding: dict) -> dict:
    clean = deepcopy(finding)
    clean["raw_description"] = redact_text(clean.get("raw_description"))
    clean["code_snippet"] = redact_text(clean.get("code_snippet"))
    return clean


def redact_findings(findings: list[dict]) -> list[dict]:
    return [redact_finding(finding) for finding in findings]


def redact_cache(cache: dict) -> dict:
    clean = deepcopy(cache)
    for entry in clean.get("files", {}).values():
        entry["bandit"] = redact_findings(entry.get("bandit", []))
        entry["secrets"] = redact_findings(entry.get("secrets", []))
    for dep_hash, findings in clean.get("dependencies", {}).items():
        clean["dependencies"][dep_hash] = redact_findings(findings)
    return clean
