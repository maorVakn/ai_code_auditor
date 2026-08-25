"""
Builds the final generic audit JSON.

Gemini is optional: in CI without GEMINI_API_KEY we still emit a useful,
stable schema. When a key is present, the model may improve summaries and
fix guidance, but it only receives already-redacted finding data.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from xmlrpc import client


GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")  # fallback to a known stable model if not set



def build_audit_report(scan_result: dict, use_ai: bool = True) -> dict:
    report = _fallback_report(scan_result)
    api_key = os.getenv("GEMINI_API_KEY")
    if not use_ai or not api_key or not scan_result.get("findings"):
        report["ai_enriched"] = False
        return report

    enriched, error = _try_gemini(report, api_key)
    if enriched is None:
        report["ai_enriched"] = False
        report["ai_error"] = f"Gemini enrichment failed; deterministic report was used. {error}"
        return report

    enriched["ai_enriched"] = True
    return enriched


def _fallback_report(scan_result: dict) -> dict:
    findings = []
    for finding in scan_result.get("findings", []):
        findings.append({
            "id": finding.get("finding_id"),
            "title": _title_for(finding),
            "severity": finding.get("severity", "UNRATED"),
            "category": finding.get("category"),
            "tool": finding.get("source_tool"),
            "rule_id": finding.get("rule_id"),
            "rule_name": finding.get("rule_name"),
            "location": {
                "file": finding.get("file"),
                "line": finding.get("line"),
            },
            "summary": finding.get("raw_description") or "Security finding detected.",
            "risk": _risk_for(finding),
            "recommended_fix": _fix_for(finding),
            "safe_for_ai_copy": _copy_prompt_for(finding),
            "references": [finding.get("more_info_url")] if finding.get("more_info_url") else [],
            "metadata": {
                "confidence": finding.get("confidence"),
                "cwe": finding.get("cwe"),
                "fix_versions": finding.get("fix_versions", []),
                "aliases": finding.get("aliases", []),
            },
        })

    return {
        "schema_version": "1.0",
        "ai_enriched": False,
        "summary": {
            "scanned_path": scan_result.get("scanned_path"),
            "total_findings": scan_result.get("total_findings", 0),
            "severity_counts": scan_result.get("severity_counts", {}),
            "files_scanned": scan_result.get("files_scanned", 0),
            "files_skipped_from_cache": scan_result.get("files_skipped_from_cache", 0),
            "tool_timings_seconds": scan_result.get("tool_timings_seconds", {}),
        },
        "findings": findings,
    }


def _try_gemini(report: dict, api_key: str) -> tuple[dict | None, str | None]:
    prompt = (
        "Return only valid JSON matching the input schema. Improve title, summary, risk, "
        "recommended_fix, and safe_for_ai_copy for each security finding. Do not add secrets, "
        "do not ask for access to private code, and keep locations/rule ids unchanged.\n\n"
        + json.dumps(report, ensure_ascii=False)
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"response_mime_type": "application/json"},
    }
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={api_key}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        enriched = json.loads(text)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:500]
        return None, f"HTTP {exc.code}: {body}"
    except (KeyError, json.JSONDecodeError, urllib.error.URLError, TimeoutError) as exc:
        return None, str(exc)

    if not isinstance(enriched, dict) or "summary" not in enriched or "findings" not in enriched:
        return None, "Gemini returned JSON that did not match the expected report schema."
    return enriched, None


def _title_for(finding: dict) -> str:
    if finding.get("category") == "exposed_secret":
        return f"Possible exposed secret in {finding.get('file')}"
    if finding.get("category") == "vulnerable_dependency":
        return f"Vulnerable dependency: {finding.get('rule_name')}"
    return finding.get("rule_name") or finding.get("rule_id") or "Security finding"


def _risk_for(finding: dict) -> str:
    category = finding.get("category")
    if category == "exposed_secret":
        return "A committed credential can allow unauthorized access if it is real."
    if category == "vulnerable_dependency":
        return "The installed package version is associated with a known vulnerability."
    return "The code pattern may be exploitable depending on how user input reaches it."


def _fix_for(finding: dict) -> str:
    if finding.get("fix_versions"):
        versions = ", ".join(finding["fix_versions"])
        return f"Upgrade the affected dependency to one of these fixed versions: {versions}."
    if finding.get("category") == "exposed_secret":
        return "Remove the secret from the repository, rotate it, and load it from a protected secret manager or CI secret."
    return "Review the flagged code path and replace it with the safer pattern recommended by the rule reference."


def _copy_prompt_for(finding: dict) -> str:
    file_path = finding.get("file")
    line = finding.get("line")
    return (
        f"Fix security finding {finding.get('rule_id')} in {file_path}"
        + (f":{line}" if line else "")
        + f". Issue: {finding.get('raw_description')}"
    )
