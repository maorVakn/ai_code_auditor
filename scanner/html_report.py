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

    # IMPORTANT: the index used here must match the position of each finding
    # inside `findings` (the same list that gets serialized to findings_json
    # below) - not any pre-sort index stored on the finding itself. The two
    # lists have to stay in lockstep or the client-side filter reads the
    # wrong finding's data.
    cards = "\n".join(
        _finding_card(finding, index) for index, finding in enumerate(findings)
    ) or "<div class=\"empty\" id=\"empty-state\">No findings detected.</div>"

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
      --med-bg: #fffbeb;
      --low: #3b82f6;
      --low-bg: #eff6ff;
      --unrated: #6b7280;
      --unrated-bg: #f3f4f6;

      --code-bg: #0f172a;
      --code-text: #f8fafc;
      --input-bg: #ffffff;
      --btn-bg: #0f172a;
      --btn-text: #ffffff;
      --btn-hover: #1e293b;

      --radius: 12px;
      --shadow: 0 1px 3px 0 rgb(0 0 0 / 0.08), 0 1px 2px -1px rgb(0 0 0 / 0.06);
      --shadow-md: 0 8px 16px -4px rgb(0 0 0 / 0.1), 0 4px 8px -4px rgb(0 0 0 / 0.06);
    }}

    [data-theme="dark"] {{
      --bg: #0b1120;
      --panel: #131c2e;
      --text: #e8edf5;
      --muted: #93a3b8;
      --line: #253048;

      --high: #f87171;
      --high-bg: #2a1414;
      --med: #fbbf24;
      --med-bg: #2a2210;
      --low: #60a5fa;
      --low-bg: #12213b;
      --unrated: #94a3b8;
      --unrated-bg: #1c2436;

      --code-bg: #050914;
      --code-text: #e8edf5;
      --input-bg: #0f1729;
      --btn-bg: #3b82f6;
      --btn-text: #0b1120;
      --btn-hover: #60a5fa;

      --shadow: 0 1px 3px 0 rgb(0 0 0 / 0.4), 0 1px 2px -1px rgb(0 0 0 / 0.3);
      --shadow-md: 0 8px 20px -4px rgb(0 0 0 / 0.55), 0 4px 10px -4px rgb(0 0 0 / 0.4);
    }}

    * {{ box-sizing: border-box; }}
    html {{ color-scheme: light; }}
    html[data-theme="dark"] {{ color-scheme: dark; }}

    body {{
      margin: 0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.55;
      -webkit-font-smoothing: antialiased;
      transition: background-color 0.15s ease, color 0.15s ease;
    }}

    header {{
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #fff;
      padding: 28px 24px;
      border-bottom: 1px solid #334155;
    }}
    .header-content {{
      max-width: 1100px;
      margin: 0 auto;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
    }}
    h1 {{ margin: 0 0 6px; font-size: 24px; font-weight: 700; letter-spacing: -0.02em; }}
    .meta {{ color: #94a3b8; margin: 0; font-size: 13px; }}

    .theme-toggle {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      height: 38px;
      padding: 0 14px;
      border-radius: 9999px;
      border: 1px solid rgba(255,255,255,0.18);
      background: rgba(255,255,255,0.06);
      color: #e2e8f0;
      cursor: pointer;
      font-size: 13px;
      font-weight: 500;
      transition: background-color 0.15s ease;
      flex-shrink: 0;
    }}
    .theme-toggle:hover {{ background: rgba(255,255,255,0.14); }}

    main {{ max-width: 1100px; margin: 0 auto; padding: 24px 20px 48px; }}

    .summary {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 14px;
      margin-bottom: 20px;
    }}
    .metric {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 16px 18px;
      box-shadow: var(--shadow);
    }}
    .metric span {{ display: block; color: var(--muted); font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }}
    .metric strong {{ font-size: 26px; font-weight: 700; color: var(--text); }}
    .metric.m-high strong {{ color: var(--high); }}
    .metric.m-med strong {{ color: var(--med); }}
    .metric.m-low strong {{ color: var(--low); }}

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
      padding: 14px 16px;
      margin-bottom: 8px;
      box-shadow: var(--shadow);
      position: sticky;
      top: 12px;
      z-index: 10;
    }}
    input, select {{
      height: 40px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--input-bg);
      padding: 0 14px;
      font: inherit;
      font-size: 14px;
      color: var(--text);
      outline: none;
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }}
    button {{
      height: 40px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--input-bg);
      padding: 0 14px;
      font: inherit;
      font-size: 14px;
      color: var(--text);
      transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }}
    input:focus, select:focus {{ border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15); }}
    button:focus-visible, .theme-toggle:focus-visible {{
      outline: 2px solid #3b82f6;
      outline-offset: 2px;
    }}
    .visually-hidden {{
      position: absolute;
      width: 1px; height: 1px;
      padding: 0; margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border: 0;
    }}
    @media (prefers-reduced-motion: reduce) {{
      *, *::before, *::after {{
        transition-duration: 0.001ms !important;
      }}
    }}
    input {{ flex: 1; min-width: 200px; }}
    select {{ cursor: pointer; }}
    .toolbar button {{
      cursor: pointer;
      background: var(--btn-bg);
      color: var(--btn-text);
      border-color: var(--btn-bg);
      font-weight: 600;
      transition: background-color 0.15s ease, opacity 0.15s ease;
      white-space: nowrap;
    }}
    .toolbar button:hover {{ background: var(--btn-hover); }}

    .result-count {{ color: var(--muted); font-size: 13px; margin: 10px 2px 18px; }}

    .finding {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius);
      padding: 20px 24px;
      margin-bottom: 14px;
      box-shadow: var(--shadow);
      transition: transform 0.1s ease, box-shadow 0.1s ease;
    }}
    .finding:hover {{ box-shadow: var(--shadow-md); }}

    .finding.sev-HIGH {{ border-left: 5px solid var(--high); }}
    .finding.sev-MEDIUM {{ border-left: 5px solid var(--med); }}
    .finding.sev-LOW {{ border-left: 5px solid var(--low); }}
    .finding.sev-UNRATED {{ border-left: 5px solid var(--unrated); }}

    .finding-head {{ display: flex; gap: 16px; justify-content: space-between; align-items: flex-start; margin-bottom: 10px; }}
    .finding-head h2 {{ margin: 0 0 6px; font-size: 17px; font-weight: 650; line-height: 1.35; }}

    .badge {{
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.03em;
      flex-shrink: 0;
    }}
    .HIGH {{ color: var(--high); background: var(--high-bg); border: 1px solid color-mix(in srgb, var(--high) 30%, transparent); }}
    .MEDIUM {{ color: var(--med); background: var(--med-bg); border: 1px solid color-mix(in srgb, var(--med) 30%, transparent); }}
    .LOW {{ color: var(--low); background: var(--low-bg); border: 1px solid color-mix(in srgb, var(--low) 30%, transparent); }}
    .UNRATED {{ color: var(--unrated); background: var(--unrated-bg); }}

    .tool {{
      display: inline-flex;
      align-items: center;
      padding: 2px 9px;
      border-radius: 6px;
      background: var(--unrated-bg);
      color: var(--muted);
      font-size: 12px;
      font-weight: 500;
      border: 1px solid var(--line);
    }}
    .row {{ display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }}
    .loc {{ color: var(--muted); font-size: 13px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}

    .finding p {{ margin: 8px 0; font-size: 14px; color: var(--muted); }}
    .finding p strong {{ color: var(--text); }}

    pre {{
      white-space: pre-wrap;
      word-break: break-word;
      background: var(--code-bg);
      color: var(--code-text);
      border-radius: 8px;
      padding: 14px 16px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 13px;
      margin: 12px 0 8px;
      overflow-x: auto;
    }}

    .copy {{
      height: 40px;
      padding: 0 14px;
      font-size: 13px;
      background: var(--unrated-bg);
      color: var(--text);
      border: 1px solid var(--line);
      margin-top: 6px;
    }}
    .copy:hover {{ background: var(--line); }}
    .copy.copied {{ background: var(--low); color: #fff; border-color: var(--low); }}

    .muted {{ color: var(--muted); font-size: 13px; }}
    .muted a {{ color: var(--low); text-decoration: none; }}
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

    @media (max-width: 600px) {{
      .toolbar {{ position: static; }}
      .finding-head {{ flex-direction: column; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="header-content">
      <div>
        <h1>Security Audit Report</h1>
        <p class="meta">Path: {html.escape(str(summary.get("scanned_path", "")))} · Sorted by severity</p>
      </div>
      <button class="theme-toggle" id="theme-toggle" onclick="toggleTheme()" aria-pressed="false" aria-label="Toggle dark mode">
        <span id="theme-icon" aria-hidden="true">🌙</span><span id="theme-label">Dark mode</span>
      </button>
    </div>
  </header>
  <main>
    <section class="summary">
      <div class="metric"><span>Total</span><strong>{summary.get("total_findings", 0)}</strong></div>
      <div class="metric m-high"><span>High</span><strong>{counts.get("HIGH", 0)}</strong></div>
      <div class="metric m-med"><span>Medium</span><strong>{counts.get("MEDIUM", 0)}</strong></div>
      <div class="metric m-low"><span>Low</span><strong>{counts.get("LOW", 0)}</strong></div>
      <div class="metric"><span>Cache skipped</span><strong>{summary.get("files_skipped_from_cache", 0)}</strong></div>
    </section>
    <section class="notice"><strong>{html.escape(ai_status)}</strong> · {html.escape(str(ai_detail))}</section>
    <section class="toolbar">
      <label class="visually-hidden" for="q">Filter findings by file, rule, or text</label>
      <input id="q" placeholder="Filter by file, rule, text..." oninput="filterFindings()">
      <label class="visually-hidden" for="sev">Filter by severity</label>
      <select id="sev" onchange="filterFindings()">
        <option value="">All severities</option>
        <option>HIGH</option>
        <option>MEDIUM</option>
        <option>LOW</option>
        <option>UNRATED</option>
      </select>
      <button onclick="copyAll()" id="copy-all-btn">Copy JSON</button>
    </section>
    <p class="result-count" id="result-count" role="status" aria-live="polite"></p>
    <section id="findings">{cards}</section>
  </main>
  <script id="findings-data" type="application/json">{findings_json}</script>
  <script>
    const findings = JSON.parse(document.getElementById('findings-data').textContent);
    const findingEls = Array.from(document.querySelectorAll('.finding'));

    function filterFindings() {{
      const q = document.getElementById('q').value.toLowerCase();
      const sev = document.getElementById('sev').value;
      let visible = 0;
      findingEls.forEach((el) => {{
        const data = findings[Number(el.dataset.index)];
        const blob = JSON.stringify(data).toLowerCase();
        const show = (!sev || data.severity === sev) && (!q || blob.includes(q));
        el.style.display = show ? '' : 'none';
        if (show) visible++;
      }});
      const countEl = document.getElementById('result-count');
      if (countEl) {{
        countEl.textContent = findingEls.length
          ? `Showing ${{visible}} of ${{findingEls.length}} finding${{findingEls.length === 1 ? '' : 's'}}`
          : '';
      }}
    }}

    function copyText(text) {{
      navigator.clipboard.writeText(text);
    }}

    function copyAll() {{
      copyText(JSON.stringify(findings, null, 2));
      const btn = document.getElementById('copy-all-btn');
      const original = btn.textContent;
      btn.setAttribute('aria-live', 'polite');
      btn.textContent = 'Copied!';
      setTimeout(() => {{ btn.textContent = original; }}, 1200);
    }}

    function flashCopied(btn) {{
      const original = btn.textContent;
      btn.setAttribute('aria-live', 'polite');
      btn.textContent = 'Copied!';
      btn.classList.add('copied');
      setTimeout(() => {{ btn.textContent = original; btn.classList.remove('copied'); }}, 1200);
    }}

    // --- theme handling ---
    function applyTheme(theme) {{
      document.documentElement.setAttribute('data-theme', theme);
      const icon = document.getElementById('theme-icon');
      const label = document.getElementById('theme-label');
      const toggleBtn = document.getElementById('theme-toggle');
      toggleBtn.setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
      if (theme === 'dark') {{
        icon.textContent = '☀️';
        label.textContent = 'Light mode';
      }} else {{
        icon.textContent = '🌙';
        label.textContent = 'Dark mode';
      }}
    }}

    function toggleTheme() {{
      const current = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
      const next = current === 'dark' ? 'light' : 'dark';
      applyTheme(next);
      try {{ localStorage.setItem('audit-report-theme', next); }} catch (e) {{ /* ignore */ }}
    }}

    (function initTheme() {{
      let saved = null;
      try {{ saved = localStorage.getItem('audit-report-theme'); }} catch (e) {{ /* ignore */ }}
      const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      applyTheme(saved || (prefersDark ? 'dark' : 'light'));
    }})();

    filterFindings();
  </script>
</body>
</html>"""


def _finding_card(finding: dict, index: int) -> str:
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
      <h2><span aria-hidden="true">{icon}</span> {title}</h2>
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
  <button class="copy" onclick="copyText(this.previousElementSibling.innerText); flashCopied(this)">Copy fix prompt</button>
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