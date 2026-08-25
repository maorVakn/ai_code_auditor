"""
Static HTML report generator for GitHub Actions artifacts.
"""
from __future__ import annotations

import html
import json


def write_html_report(report: dict, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(render_html_report(report))


def render_html_report(report: dict) -> str:
    summary = report.get("summary", {})
    findings = _sorted_findings(report.get("findings", []))
    counts = summary.get("severity_counts", {})
    findings_json = _safe_json_for_script(findings)
    ai_status = "AI enriched" if report.get("ai_enriched") else "Local fallback"
    ai_detail = report.get("ai_error") or "Gemini enrichment completed." if report.get("ai_enriched") else report.get("ai_error") or "Gemini was not configured or was disabled."

    cards = "\n".join(_finding_card(finding) for finding in findings) or "<p class=\"empty\">No findings detected.</p>"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Audit Report</title>
  <style>
    :root {{ color-scheme: light; --bg:#f5f7fb; --panel:#fff; --text:#17202a; --muted:#5d6978; --line:#d9dee7; --high:#b42318; --med:#b54708; --low:#175cd3; --ok:#067647; --soft:#eef2f7; }}
    * {{ box-sizing: border-box; }}
    body {{ margin:0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:var(--bg); color:var(--text); }}
    header {{ background:#17202a; color:#fff; padding:24px; border-bottom:4px solid #2f6fed; }}
    main {{ max-width:1100px; margin:0 auto; padding:20px; }}
    h1 {{ margin:0 0 8px; font-size:28px; }}
    h2 {{ margin:0; font-size:18px; }}
    .meta {{ color:#cbd5e1; margin:0; }}
    .toolbar, .summary, .finding, .notice {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; }}
    .summary {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap:12px; padding:16px; margin:16px 0; }}
    .metric span {{ display:block; color:var(--muted); font-size:12px; }}
    .metric strong {{ font-size:24px; }}
    .notice {{ padding:12px 14px; margin:16px 0; color:var(--muted); }}
    .notice strong {{ color:var(--text); }}
    .toolbar {{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; padding:12px; margin-bottom:16px; }}
    input, select, button {{ min-height:36px; border:1px solid var(--line); border-radius:6px; background:#fff; padding:0 10px; font:inherit; }}
    button {{ cursor:pointer; background:#111827; color:#fff; border-color:#111827; }}
    .finding {{ margin:12px 0; padding:16px; border-left:5px solid var(--line); }}
    .finding.sev-HIGH {{ border-left-color:var(--high); }}
    .finding.sev-MEDIUM {{ border-left-color:var(--med); }}
    .finding.sev-LOW {{ border-left-color:var(--low); }}
    .finding-head {{ display:flex; gap:12px; justify-content:space-between; align-items:flex-start; }}
    .badge {{ display:inline-flex; align-items:center; min-height:24px; padding:0 8px; border-radius:999px; font-size:12px; font-weight:700; }}
    .HIGH {{ color:#fff; background:var(--high); }} .MEDIUM {{ color:#fff; background:var(--med); }} .LOW {{ color:#fff; background:var(--low); }} .UNRATED {{ color:#111827; background:#e5e7eb; }}
    .tool {{ display:inline-flex; align-items:center; min-height:22px; padding:0 7px; border-radius:6px; background:var(--soft); color:#374151; font-size:12px; font-weight:600; }}
    .row {{ display:flex; gap:8px; flex-wrap:wrap; margin-top:8px; }}
    .loc, .muted {{ color:var(--muted); }}
    pre {{ white-space:pre-wrap; word-break:break-word; background:#f3f4f6; border:1px solid var(--line); border-radius:6px; padding:10px; }}
    .copy {{ margin-top:10px; }}
    .empty {{ background:#fff; border:1px solid var(--line); border-radius:8px; padding:20px; }}
  </style>
</head>
<body>
  <header>
    <h1>Security Audit Report</h1>
    <p class="meta">Path: {html.escape(str(summary.get("scanned_path", "")))} · Sorted by severity</p>
  </header>
  <main>
    <section class="summary">
      <div class="metric"><span>Total</span><strong>{summary.get("total_findings", 0)}</strong></div>
      <div class="metric"><span>High</span><strong>{counts.get("HIGH", 0)}</strong></div>
      <div class="metric"><span>Medium</span><strong>{counts.get("MEDIUM", 0)}</strong></div>
      <div class="metric"><span>Low</span><strong>{counts.get("LOW", 0)}</strong></div>
      <div class="metric"><span>Cache skipped</span><strong>{summary.get("files_skipped_from_cache", 0)}</strong></div>
    </section>
    <section class="notice"><strong>{html.escape(ai_status)}</strong> · {html.escape(str(ai_detail))}</section>
    <section class="toolbar">
      <input id="q" placeholder="Filter by file, rule, text" oninput="filterFindings()">
      <select id="sev" onchange="filterFindings()">
        <option value="">All severities</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>UNRATED</option>
      </select>
      <button onclick="copyAll()">Copy JSON</button>
    </section>
    <section id="findings">{cards}</section>
  </main>
  <script id="findings-data" type="application/json">{findings_json}</script>
  <script>
    const findings = JSON.parse(document.getElementById('findings-data').textContent);
    function filterFindings() {{
      const q = document.getElementById('q').value.toLowerCase();
      const sev = document.getElementById('sev').value;
      document.querySelectorAll('.finding').forEach((el) => {{
        const data = findings[Number(el.dataset.index)];
        const blob = JSON.stringify(data).toLowerCase();
        el.style.display = (!sev || data.severity === sev) && (!q || blob.includes(q)) ? '' : 'none';
      }});
    }}
    function copyText(text) {{ navigator.clipboard.writeText(text); }}
    function copyAll() {{ copyText(JSON.stringify(findings, null, 2)); }}
  </script>
</body>
</html>"""


def _finding_card(finding: dict) -> str:
    index = html.escape(str(finding.get("_index", "")))
    severity = html.escape(str(finding.get("severity", "UNRATED")))
    icon = html.escape(_severity_icon(finding.get("severity", "UNRATED")))
    title = html.escape(str(finding.get("title", "Security finding")))
    location = finding.get("location", {})
    loc = html.escape(f"{location.get('file')}:{location.get('line')}" if location.get("line") else str(location.get("file")))
    refs = " ".join(f"<a href=\"{html.escape(url, quote=True)}\">reference</a>" for url in finding.get("references", []) if url)
    tool = html.escape(str(finding.get("tool") or "unknown"))
    category = html.escape(str(finding.get("category") or "security"))
    rule = html.escape(str(finding.get("rule_id") or finding.get("rule_name") or "rule"))
    return f"""<article class="finding sev-{severity}" data-index="{index}">
  <div class="finding-head"><div><h2>{icon} {title}</h2><div class="loc">{loc}</div><div class="row"><span class="tool">{tool}</span><span class="tool">{category}</span><span class="tool">{rule}</span></div></div><span class="badge {severity}">{severity}</span></div>
  <p>{html.escape(str(finding.get("summary", "")))}</p>
  <p><strong>Risk:</strong> {html.escape(str(finding.get("risk", "")))}</p>
  <p><strong>Fix:</strong> {html.escape(str(finding.get("recommended_fix", "")))}</p>
  <pre>{html.escape(str(finding.get("safe_for_ai_copy", "")))}</pre>
  <button class="copy" onclick="copyText(this.previousElementSibling.innerText)">Copy fix prompt</button>
  <p class="muted">{refs}</p>
</article>"""


def _safe_json_for_script(value: object) -> str:
    return (
        json.dumps(value, ensure_ascii=False)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def _sorted_findings(findings: list[dict]) -> list[dict]:
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNRATED": 3}
    return sorted(
        findings,
        key=lambda finding: (
            severity_order.get(finding.get("severity", "UNRATED"), 4),
            str(finding.get("tool") or ""),
            str(finding.get("location", {}).get("file") or ""),
            finding.get("location", {}).get("line") or 0,
        ),
    )


def _severity_icon(severity: str) -> str:
    return {"HIGH": "!", "MEDIUM": "^", "LOW": "i", "UNRATED": "-"}.get(severity, "-")
