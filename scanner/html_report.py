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

    cards = "\n".join(_finding_card(finding) for finding in findings) or "<div class=\"empty\">No findings detected.</div>"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Audit Report</title>
  <style>
    :root {{
      --bg: #f8fafc;
      --panel: #ffffff;
      --text: #0f172a;
      --muted: #64748b;
      --line: #e2e8f0;
      
      --high: #ef4444;
      --high-bg: #fef2f2;
      --med: #f59e0b;
      --med-bg: #fffbe6;
      --low: #3b82f6;
      --low-bg: #eff6ff;
      --unrated: #6b7280;
      --unrated-bg: #f3f4f6;
      --ok: #10b981;
      
      --radius: 10px;
      --shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);
      --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
    }}
    
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }}
    
    header {{
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #fff;
      padding: 32px 24px;
      border-bottom: 1px solid #334155;
    }}
    .header-content {{ max-width: 1100px; margin: 0 auto; }}
    h1 {{ margin: 0 0 6px; font-size: 26px; font-weight: 700; letter-spacing: -0.02em; }}
    .meta {{ color: #94a3b8; margin: 0; font-size: 14px; }}
    
    main {{ max-width: 1100px; margin: 0 auto; padding: 24px 20px 48px; }}
    
    .summary {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 16px;
      margin-bottom: 20px;
    }}
    .metric {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 16px 20px;
      box-shadow: var(--shadow);
    }}
    .metric span {{ display: block; color: var(--muted); font-size: 13px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 4px; }}
    .metric strong {{ font-size: 28px; font-weight: 700; color: var(--text); }}
    
    .notice {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-left: 4px solid var(--low);
      border-radius: var(--radius);
      padding: 14px 18px;
      margin-bottom: 20px;
      color: var(--muted);
      font-size: 14px;
      box-shadow: var(--shadow);
    }}
    .notice strong {{ color: var(--text); font-weight: 600; }}
    
    .toolbar {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 14px 18px;
      margin-bottom: 24px;
      box-shadow: var(--shadow);
    }}
    input, select, button {{
      height: 40px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      padding: 0 14px;
      font: inherit;
      font-size: 14px;
      color: var(--text);
      outline: none;
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }}
    input:focus, select:focus {{ border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15); }}
    input {{ flex: 1; min-width: 200px; }}
    select {{ cursor: pointer; }}
    button {{
      cursor: pointer;
      background: #0f172a;
      color: #fff;
      border-color: #0f172a;
      font-weight: 500;
      transition: background-color 0.15s ease;
    }}
    button:hover {{ background: #1e293b; }}
    
    .finding {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 20px 24px;
      margin-bottom: 16px;
      box-shadow: var(--shadow);
      transition: transform 0.1s ease, box-shadow 0.1s ease;
    }}
    .finding:hover {{ box-shadow: var(--shadow-md); }}
    
    .finding.sev-HIGH {{ border-left: 5px solid var(--high); }}
    .finding.sev-MEDIUM {{ border-left: 5px solid var(--med); }}
    .finding.sev-LOW {{ border-left: 5px solid var(--low); }}
    .finding.sev-UNRATED {{ border-left: 5px solid var(--unrated); }}
    
    .finding-head {{ display: flex; gap: 16px; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }}
    .finding-head h2 {{ margin: 0 0 6px; font-size: 18px; font-weight: 600; line-height: 1.3; }}
    
    .badge {{
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.03em;
    }}
    .HIGH {{ color: var(--high); background: var(--high-bg); border: 1px solid rgba(239,68,68,0.2); }}
    .MEDIUM {{ color: #d97706; background: var(--med-bg); border: 1px solid rgba(245,158,11,0.2); }}
    .LOW {{ color: var(--low); background: var(--low-bg); border: 1px solid rgba(59,130,246,0.2); }}
    .UNRATED {{ color: var(--unrated); background: var(--unrated-bg); }}
    
    .tool {{
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      border-radius: 4px;
      background: #f1f5f9;
      color: #475569;
      font-size: 12px;
      font-weight: 500;
      border: 1px solid #e2e8f0;
    }}
    .row {{ display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }}
    .loc {{ color: var(--muted); font-size: 13px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    
    .finding p {{ margin: 8px 0; font-size: 14px; color: #334155; }}
    .finding p strong {{ color: var(--text); }}
    
    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      background: #0f172a;
      color: #f8fafc;
      border-radius: 6px;
      padding: 14px 16px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 13px;
      margin: 12px 0 8px;
      overflow-x: auto;
    }}
    
    .copy {{
      height: 32px;
      padding: 0 12px;
      font-size: 12px;
      background: #f1f5f9;
      color: #334155;
      border: 1px solid #cbd5e1;
      margin-top: 6px;
    }}
    .copy:hover {{ background: #e2e8f0; color: #0f172a; }}
    
    .muted {{ color: var(--muted); font-size: 13px; }}
    .muted a {{ color: #2563eb; text-decoration: none; }}
    .muted a:hover {{ text-decoration: underline; }}
    
    .empty {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 40px;
      text-align: center;
      color: var(--muted);
      font-size: 16px;
    }}
  </style>
</head>
<body>
  <header>
    <div class="header-content">
      <h1>Security Audit Report</h1>
      <p class="meta">Path: {html.escape(str(summary.get("scanned_path", "")))} · Sorted by severity</p>
    </div>
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
      <input id="q" placeholder="Filter by file, rule, text..." oninput="filterFindings()">
      <select id="sev" onchange="filterFindings()">
        <option value="">All severities</option>
        <option>HIGH</option>
        <option>MEDIUM</option>
        <option>LOW</option>
        <option>UNRATED</option>
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
    refs = " ".join(f"<a href=\"{html.escape(url, quote=True)}\" target=\"_blank\" rel=\"noopener\">Reference</a>" for url in finding.get("references", []) if url)
    tool = html.escape(str(finding.get("tool") or "unknown"))
    category = html.escape(str(finding.get("category") or "security"))
    rule = html.escape(str(finding.get("rule_id") or finding.get("rule_name") or "rule"))
    return f"""<article class="finding sev-{severity}" data-index="{index}">
  <div class="finding-head">
    <div>
      <h2>{icon} {title}</h2>
      <div class="loc">{loc}</div>
      <div class="row">
        <span class="tool">{tool}</span>
        <span class="tool">{category}</span>
        <span class="tool">{rule}</span>
      </div>
    </div>
    <span class="badge {severity}">{severity}</span>
  </div>
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
    return {"HIGH": "🚨", "MEDIUM": "⚠️", "LOW": "ℹ️", "UNRATED": "🔍"}.get(severity, "🔍")