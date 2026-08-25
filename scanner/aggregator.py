"""
Merges the results of all scanners (bandit, detect-secrets, pip-audit)
into a single finding list, and assigns a unique ID to each finding.
This is the output of "stage 1" in the architecture - before it gets
sent to the AI.

Two performance techniques are used together:

1. Concurrency: the three tools each run in a separate thread
   (ThreadPoolExecutor) instead of sequentially. This makes sense
   because each of them essentially launches an external subprocess
   and waits for it - meaning the thread spends most of its time
   "sleeping" on I/O, not doing actual computation. This is the
   classic case where threads help in Python despite the GIL, because
   the GIL is released while waiting on a subprocess.

2. Content-hash caching (scanner/cache.py): before running bandit or
   detect-secrets, every file's content is hashed. Files whose hash
   matches a previous run are skipped entirely - only new or changed
   files are actually sent to the tools. The same applies to
   requirements.txt for pip-audit. This matters most in CI/CD: a PR
   that touches one file out of a hundred shouldn't re-scan the other
   ninety-nine or re-hit osv.dev for unchanged dependencies.
"""
from __future__ import annotations

import hashlib
import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.ai_report import build_audit_report
from scanner.bandit_scan import run_bandit
from scanner.secrets_scan import run_secrets_scan
from scanner.deps_scan import run_deps_scan
from scanner.html_report import write_html_report
from scanner.markdown_report import write_markdown_report
from scanner import cache as cache_module
from scanner.redaction import redact_cache, redact_findings

# directories we never want to walk into when collecting files to scan
IGNORED_DIRS = {".git", "venv", ".venv", "__pycache__", "node_modules"}


def _make_finding_id(finding: dict) -> str:
    """Creates a stable, short ID for a finding, based on its fixed
    content (not tied to runtime)."""
    key = f"{finding['source_tool']}:{finding['rule_id']}:{finding['file']}:{finding['line']}"
    return hashlib.sha256(key.encode()).hexdigest()[:10]


def _collect_files(root_path: str) -> list[str]:
    """Walks root_path and returns every file path (relative), skipping
    noise directories like .git and venv."""
    if os.path.isfile(root_path):
        return [root_path]

    collected = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            if fname == ".audit_cache.json":
                continue
            collected.append(os.path.join(dirpath, fname))
    return collected


def _partition_by_cache(cache: dict, files: list[str]) -> tuple[list[str], dict]:
    """
    Splits files into two groups based on the cache:
    - changed_files: need to be (re)scanned by bandit/detect-secrets
    - cached_findings: {"bandit": [...], "secrets": [...]} already
      known and valid for unchanged files - reused as-is
    Returns (changed_files, cached_findings).
    """
    changed_files = []
    cached_bandit = []
    cached_secrets = []

    for file_path in files:
        try:
            file_hash = cache_module.compute_file_hash(file_path)
        except (OSError, IOError):
            continue  # unreadable file, skip silently

        hit = cache_module.get_cached_file_findings(cache, file_path, file_hash)
        if hit is not None:
            cached_bandit += hit["bandit"]
            cached_secrets += hit["secrets"]
        else:
            changed_files.append(file_path)

    return changed_files, {"bandit": cached_bandit, "secrets": cached_secrets}


def run_full_scan(
    code_path: str,
    requirements_path: str | None = None,
    verbose: bool = True,
    use_cache: bool = True,
    cache_path: str = cache_module.DEFAULT_CACHE_PATH,
) -> dict:
    """
    Runs a full scan: code (bandit + secrets) and dependencies (if a
    requirements file is supplied). The three tools run concurrently,
    and unchanged files/dependencies (per the on-disk cache) are
    skipped entirely rather than re-scanned.
    """
    if requirements_path is None:
        guess = os.path.join(code_path, "requirements.txt")
        if os.path.isfile(guess):
            requirements_path = guess

    cache = redact_cache(cache_module.load_cache(cache_path)) if use_cache else {"files": {}, "dependencies": {}}

    all_files = _collect_files(code_path)
    changed_files, cached_findings = _partition_by_cache(cache, all_files)

    if verbose:
        skipped = len(all_files) - len(changed_files)
        print(f"[cache] {skipped}/{len(all_files)} files unchanged, skipping re-scan", file=sys.stderr)

    # dependencies: hash the whole requirements.txt content, reuse
    # cached findings if it's byte-for-byte identical to a past run
    deps_hash = None
    cached_deps_findings = None
    if requirements_path and os.path.isfile(requirements_path):
        with open(requirements_path) as f:
            deps_hash = cache_module.compute_text_hash(f.read())
        cached_deps_findings = cache_module.get_cached_dependency_findings(cache, deps_hash) if use_cache else None

    # only build tasks for tools that actually have new work to do
    tasks = {}
    if changed_files:
        tasks["bandit"] = lambda: run_bandit(changed_files)
        tasks["detect-secrets"] = lambda: run_secrets_scan(changed_files)
    if requirements_path and os.path.isfile(requirements_path) and cached_deps_findings is None:
        tasks["pip-audit"] = lambda: run_deps_scan(requirements_path)

    fresh_bandit_findings = []
    fresh_secrets_findings = []
    fresh_deps_findings = cached_deps_findings if cached_deps_findings is not None else []
    timings = {}

    if tasks:
        with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
            future_to_name = {executor.submit(_timed(func)): name for name, func in tasks.items()}

            for future in as_completed(future_to_name):
                name = future_to_name[future]
                result, elapsed = future.result()
                timings[name] = round(elapsed, 2)
                if name == "bandit":
                    fresh_bandit_findings = result
                elif name == "detect-secrets":
                    fresh_secrets_findings = result
                elif name == "pip-audit":
                    fresh_deps_findings = result
                if verbose:
                    print(f"[{name}] finished in {elapsed:.2f}s, {len(result)} findings", file=sys.stderr)
    elif verbose:
        print("[cache] nothing changed - all results served from cache", file=sys.stderr)

    # update the cache with fresh results, grouped back by file
    if use_cache:
        fresh_bandit_findings = redact_findings(fresh_bandit_findings)
        fresh_secrets_findings = redact_findings(fresh_secrets_findings)
        fresh_deps_findings = redact_findings(fresh_deps_findings)
        _update_file_cache(cache, changed_files, fresh_bandit_findings, fresh_secrets_findings)
        if deps_hash and cached_deps_findings is None:
            cache_module.set_cached_dependency_findings(cache, deps_hash, fresh_deps_findings)
        cache_module.save_cache(cache, cache_path)

    findings = (
        cached_findings["bandit"] + fresh_bandit_findings
        + cached_findings["secrets"] + fresh_secrets_findings
        + fresh_deps_findings
    )
    findings = redact_findings(findings)

    for finding in findings:
        finding["finding_id"] = _make_finding_id(finding)

    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNRATED": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    return {
        "scanned_path": code_path,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "tool_timings_seconds": timings,
        "files_scanned": len(changed_files),
        "files_skipped_from_cache": len(all_files) - len(changed_files),
        "findings": findings,
    }


def _update_file_cache(
    cache: dict, changed_files: list[str], bandit_findings: list[dict], secrets_findings: list[dict]
) -> None:
    """Writes fresh per-file results back into the cache, grouped by
    which file each finding belongs to."""
    bandit_by_file: dict[str, list] = {}
    for f in bandit_findings:
        bandit_by_file.setdefault(f["file"], []).append(f)

    secrets_by_file: dict[str, list] = {}
    for f in secrets_findings:
        secrets_by_file.setdefault(f["file"], []).append(f)

    for file_path in changed_files:
        try:
            file_hash = cache_module.compute_file_hash(file_path)
        except (OSError, IOError):
            continue
        cache_module.set_cached_file_findings(
            cache,
            file_path,
            file_hash,
            bandit_by_file.get(file_path, []),
            secrets_by_file.get(file_path, []),
        )

 
def _timed(func):
    """Wraps a function so it also returns how long it took - useful
    for measurement/debugging."""
    def wrapper():
        start = time.perf_counter()
        result = func()
        elapsed = time.perf_counter() - start
        return result, elapsed
    return wrapper


def main() -> int:
    parser = argparse.ArgumentParser(description="Run security scanners and emit JSON/HTML reports.")
    parser.add_argument("code_path", nargs="?", default=".")
    parser.add_argument("requirements_path", nargs="?")
    parser.add_argument("--report-json", help="Write AI-ready generic report JSON to this path.")
    parser.add_argument("--html", help="Write static HTML report to this path.")
    parser.add_argument("--markdown", help="Write GitHub Actions summary markdown to this path.")
    parser.add_argument("--no-ai", action="store_true", help="Disable optional Gemini enrichment.")
    parser.add_argument("--no-cache", action="store_true", help="Run scanners without reading or writing .audit_cache.json.")
    parser.add_argument("--cache-path", default=cache_module.DEFAULT_CACHE_PATH)
    args = parser.parse_args()

    result = run_full_scan(
        args.code_path,
        args.requirements_path,
        use_cache=not args.no_cache,
        cache_path=args.cache_path,
    )

    if args.report_json or args.html or args.markdown:
        report = build_audit_report(result, use_ai=not args.no_ai)
        for index, finding in enumerate(report.get("findings", [])):
            finding["_index"] = index
        if args.report_json:
            with open(args.report_json, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        if args.html:
            write_html_report(report, args.html)
        if args.markdown:
            write_markdown_report(report, args.markdown)

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
