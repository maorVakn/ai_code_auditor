"""
GitHub Actions Step Summary report.

This gives users the important findings directly in the workflow page,
without downloading the HTML artifact.
"""
from __future__ import annotations


MAX_SUMMARY_FINDINGS = 30
MAX_CELL_LENGTH = 220


def write_markdown_report(report: dict, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(render_markdown_report(report))


def render_markdown_report(report: dict) -> str:
    summary = report.get("summary", {})
    counts = summary.get("severity_counts", {})
    findings = report.get("findings", [])

    lines = [
        "## Security audit report",
        "",
        f"**Total findings:** {summary.get('total_findings', 0)}",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
        f"| HIGH | {counts.get('HIGH', 0)} |",
        f"| MEDIUM | {counts.get('MEDIUM', 0)} |",
        f"| LOW | {counts.get('LOW', 0)} |",
        f"| UNRATED | {counts.get('UNRATED', 0)} |",
        "",
        f"**Cache:** scanned {summary.get('files_scanned', 0)} changed file(s), skipped {summary.get('files_skipped_from_cache', 0)} unchanged file(s).",
        "",
    ]

    if not findings:
        lines += ["No findings detected.", ""]
        return "\n".join(lines)

    lines += [
        "### Findings",
        "",
        "| Severity | Tool | Location | Rule | Fix prompt |",
        "| --- | --- | --- | --- | --- |",
    ]

    visible_findings = _visible_findings(findings)
    for finding in visible_findings:
        location = finding.get("location", {})
        line = location.get("line")
        loc = str(location.get("file") or "")
        if line:
            loc = f"{loc}:{line}"
        lines.append(
            "| {severity} | `{tool}` | `{location}` | `{rule}` | {prompt} |".format(
                severity=_md(_severity_label(finding.get("severity", "UNRATED"))),
                tool=_md(finding.get("tool") or "unknown"),
                location=_md(loc),
                rule=_md(finding.get("rule_id") or finding.get("rule_name") or ""),
                prompt=_truncate(_md(finding.get("safe_for_ai_copy") or finding.get("summary") or "")),
            )
        )

    remaining = len(findings) - len(visible_findings)
    if remaining > 0:
        lines += ["", f"_Showing the highest priority {len(visible_findings)} findings. Download the HTML artifact for {remaining} more._"]

    lines.append("")
    lines += _ai_status_lines(report)
    return "\n".join(lines)


def _md(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def _truncate(value: str) -> str:
    if len(value) <= MAX_CELL_LENGTH:
        return value
    return value[: MAX_CELL_LENGTH - 1].rstrip() + "..."


def _visible_findings(findings: list[dict]) -> list[dict]:
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNRATED": 3}
    ordered = sorted(
        findings,
        key=lambda finding: (
            severity_order.get(finding.get("severity", "UNRATED"), 4),
            str(finding.get("tool") or ""),
            str(finding.get("location", {}).get("file") or ""),
            finding.get("location", {}).get("line") or 0,
        ),
    )
    return ordered[:MAX_SUMMARY_FINDINGS]


def _severity_label(severity: str) -> str:
    icons = {"HIGH": "!", "MEDIUM": "^", "LOW": "i", "UNRATED": "-"}
    return f"{icons.get(severity, '-')} {severity}"


def _ai_status_lines(report: dict) -> list[str]:
    if report.get("ai_enriched"):
        return ["", "**AI:** Gemini enrichment completed.", ""]
    if report.get("ai_error"):
        return ["", f"**AI:** Gemini failed, local fallback used. `{_md(report['ai_error'])}`", ""]
    return ["", "**AI:** Local fallback used. Set `GEMINI_API_KEY` to enable Gemini enrichment.", ""]
