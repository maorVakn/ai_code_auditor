"""
Builds the final generic audit JSON.

Gemini is optional: in CI without GEMINI_API_KEY we still emit a useful,
stable schema. When a key is present, the model may improve summaries and
fix guidance, but it only receives already-redacted finding data.

AI enrichment is done in small per-finding chunks (not the whole report at
once) so that:
  - payloads stay small -> faster generation -> no more read timeouts
  - a single bad/oversized finding can't sink the whole report
  - if a model name is retired or overloaded, we fail over to the next
    model / retry instead of giving up immediately
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

# Ordered list of models to try, most-preferred first. Override with
# GEMINI_MODEL="model-a,model-b,model-c" (comma separated) if you need to
# pin something specific. Keep this list updated as Google retires models -
# check https://ai.google.dev/gemini-api/docs/changelog periodically.
_DEFAULT_MODELS = "gemini-2.5-flash,gemini-2.5-flash-lite,gemini-3.1-flash-lite"
GEMINI_MODELS = [m.strip() for m in os.getenv("GEMINI_MODEL", _DEFAULT_MODELS).split(",") if m.strip()]

GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

# How many findings to send to the model per request. Bigger chunks mean
# fewer total API calls (easier on RPM quotas) at the cost of a slightly
# bigger/slower individual request. 12 is a reasonable middle ground for
# free-tier RPM limits; drop it back down if you hit response-size issues.
CHUNK_SIZE = int(os.getenv("GEMINI_CHUNK_SIZE", "12"))

# Per-request timeout. Because each request now only carries a handful of
# findings instead of the entire report, this no longer needs to be huge.
REQUEST_TIMEOUT_SECONDS = int(os.getenv("GEMINI_TIMEOUT_SECONDS", "45"))

# Retry behaviour for transient failures (mainly 503s / connection errors).
MAX_RETRIES_PER_MODEL = 2
RETRY_BACKOFF_BASE_SECONDS = 2  # 2s, then 4s, ...

# Pause between successive chunk requests so we don't burst through the
# free-tier requests-per-minute quota when a report has many findings.
# Set to 0 to disable (e.g. if you're on a paid tier with high RPM limits).
INTER_CHUNK_DELAY_SECONDS = float(os.getenv("GEMINI_INTER_CHUNK_DELAY_SECONDS", "4"))


def build_audit_report(scan_result: dict, use_ai: bool = True) -> dict:
    report = _fallback_report(scan_result)
    api_key = os.getenv("GEMINI_API_KEY")
    if not use_ai or not api_key or not scan_result.get("findings"):
        report["ai_enriched"] = False
        return report

    findings = report["findings"]
    chunks = [findings[i:i + CHUNK_SIZE] for i in range(0, len(findings), CHUNK_SIZE)]

    enriched_findings: list[dict] = []
    chunk_errors: list[str] = []
    any_chunk_succeeded = False

    for chunk_index, chunk in enumerate(chunks):
        enriched_chunk, error = _try_gemini_chunk(chunk)
        if enriched_chunk is None:
            # Fall back to the deterministic findings for just this chunk,
            # rather than failing the entire report.
            chunk_errors.append(f"chunk {chunk_index}: {error}")
            enriched_findings.extend(chunk)
        else:
            any_chunk_succeeded = True
            enriched_findings.extend(enriched_chunk)

        is_last_chunk = chunk_index == len(chunks) - 1
        if not is_last_chunk and INTER_CHUNK_DELAY_SECONDS > 0:
            time.sleep(INTER_CHUNK_DELAY_SECONDS)

    report["findings"] = enriched_findings
    report["ai_enriched"] = any_chunk_succeeded
    if chunk_errors:
        report["ai_error"] = (
            f"Gemini enrichment partially failed ({len(chunk_errors)}/{len(chunks)} chunks); "
            f"deterministic values were used for those findings. Details: {'; '.join(chunk_errors)}"
        )
    return report


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


def _try_gemini_chunk(findings_chunk: list[dict]) -> tuple[list[dict] | None, str | None]:
    """Send a small batch of findings to Gemini and return the enriched batch.

    Tries each configured model in order; within each model, retries a
    couple of times on transient errors (503s, timeouts, connection resets)
    with exponential backoff before moving on to the next model.
    """
    prompt = (
        "Return only a valid JSON array (no prose, no markdown fences) with exactly "
        f"{len(findings_chunk)} objects, matching the input schema. Improve title, "
        "summary, risk, recommended_fix, and safe_for_ai_copy for each security finding. "
        "Do not add secrets, do not ask for access to private code, and keep id/severity/"
        "category/tool/rule_id/rule_name/location/metadata fields unchanged.\n\n"
        + json.dumps(findings_chunk, ensure_ascii=False)
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"response_mime_type": "application/json"},
    }
    body = json.dumps(payload).encode("utf-8")

    last_error = "unknown error"
    for model in GEMINI_MODELS:
        for attempt in range(1, MAX_RETRIES_PER_MODEL + 1):
            try:
                enriched = _call_gemini(model, body)
                if not isinstance(enriched, list) or len(enriched) != len(findings_chunk):
                    last_error = f"{model}: response shape mismatch"
                    break  # don't retry a bad shape, try next model instead
                return enriched, None
            except _RetryableError as exc:
                last_error = f"{model}: {exc}"
                if attempt < MAX_RETRIES_PER_MODEL:
                    is_rate_limit = "HTTP 429" in str(exc)
                    delay = 20 if is_rate_limit else RETRY_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
                    time.sleep(delay)
                    continue
                # exhausted retries for this model, fall through to next model
            except _FatalModelError as exc:
                # e.g. 404 model not found - no point retrying, try next model
                last_error = f"{model}: {exc}"
                break
            except (KeyError, json.JSONDecodeError) as exc:
                last_error = f"{model}: bad response format ({exc})"
                break

    return None, last_error


class _RetryableError(Exception):
    """Transient failure worth retrying (timeouts, 503, connection issues)."""


class _FatalModelError(Exception):
    """Non-retryable failure for this model (e.g. 404 unknown model, 400 bad request)."""


def _call_gemini(model: str, body: bytes) -> list[dict]:
    api_key = os.getenv("GEMINI_API_KEY")
    url = f"{GEMINI_API_BASE}/{model}:generateContent?key={api_key}"
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")[:500]
        if exc.code == 503 or exc.code == 429:
            raise _RetryableError(f"HTTP {exc.code}: {error_body}") from exc
        raise _FatalModelError(f"HTTP {exc.code}: {error_body}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise _RetryableError(str(exc)) from exc

    text = data["candidates"][0]["content"]["parts"][0]["text"]
    return json.loads(text)


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