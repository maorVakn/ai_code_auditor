"""
Merges the results of all scanners (bandit, detect-secrets, pip-audit)
into a single finding list, and assigns a unique ID to each finding.
This is the output of "stage 1" in the architecture - before it gets
sent to the AI.

The three tools each run in a separate thread (ThreadPoolExecutor)
instead of sequentially. This makes sense because each of them
essentially launches an external subprocess and waits for it - meaning
the thread spends most of its time "sleeping" on I/O, not doing actual
computation. This is the classic case where threads help in Python
despite the GIL, because the GIL is released while waiting on a
subprocess.
"""
import hashlib
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner.bandit_scan import run_bandit
from scanner.secrets_scan import run_secrets_scan
from scanner.deps_scan import run_deps_scan


def _make_finding_id(finding: dict) -> str:
    """Creates a stable, short ID for a finding, based on its fixed
    content (not tied to runtime)."""
    key = f"{finding['source_tool']}:{finding['rule_id']}:{finding['file']}:{finding['line']}"
    return hashlib.sha256(key.encode()).hexdigest()[:10]


def run_full_scan(code_path: str, requirements_path: str | None = None, verbose: bool = True) -> dict:
    """
    Runs a full scan: code (bandit + secrets) and dependencies (if a
    requirements file is supplied). The three tools run concurrently.
    The function returns a result only after all of them finish -
    i.e. it waits for the slowest one, it does not block on each tool
    sequentially.
    """
    if requirements_path is None:
        guess = os.path.join(code_path, "requirements.txt")
        if os.path.isfile(guess):
            requirements_path = guess

    # Define which tasks will run - each one is (display_name, callable)
    tasks = {
        "bandit": lambda: run_bandit(code_path),
        "detect-secrets": lambda: run_secrets_scan(code_path),
    }
    if requirements_path and os.path.isfile(requirements_path):
        tasks["pip-audit"] = lambda: run_deps_scan(requirements_path)

    findings = []
    timings = {}

    # max_workers=len(tasks): each tool gets its own thread, all start together
    with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        future_to_name = {
            executor.submit(_timed(func)): name
            for name, func in tasks.items()
        }

        # as_completed yields each future as soon as it finishes - not
        # in submission order, but in the order tools actually finish.
        # This way a fast tool doesn't wait on a slow one.
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            result, elapsed = future.result()
            timings[name] = round(elapsed, 2)
            findings += result
            if verbose:
                print(f"[{name}] finished in {elapsed:.2f}s, {len(result)} findings", file=sys.stderr)

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
        "findings": findings,
    }


def _timed(func):
    """Wraps a function so it also returns how long it took - useful
    for measurement/debugging."""
    def wrapper():
        start = time.perf_counter()
        result = func()
        elapsed = time.perf_counter() - start
        return result, elapsed
    return wrapper


if __name__ == "__main__":
    import sys
    import json

    code_path = sys.argv[1] if len(sys.argv) > 1 else "."
    req_path = sys.argv[2] if len(sys.argv) > 2 else None

    result = run_full_scan(code_path, req_path)
    print(json.dumps(result, indent=2, ensure_ascii=False))
