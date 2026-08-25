# AI Code Security Auditor

A Python tool that scans a code repository for security issues, builds an
AI-ready JSON report, and publishes a static HTML report for GitHub Actions.

Three tools run concurrently (separate threads) and their output is merged
into one unified finding format:

- `bandit` - scans Python code (AST-based) for issues like SQL injection,
  command injection, weak crypto, unsafe YAML loading, etc.
- `detect-secrets` - scans all files (including dotfiles like `.env`) for
  exposed credentials, using both known patterns (AWS keys, GitHub
  tokens...) and high-entropy string detection.
- `pip-audit` - checks `requirements.txt` against the osv.dev vulnerability
  database for known CVEs in dependencies.

## Setup

Requires Python 3.10+ (uses `list[dict]` / `str | None` syntax).

```bash
python3 -m venv venv
source venv/bin/activate        # on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

Run from the project root:

```bash
python3 -m scanner.aggregator <path_to_code> <path_to_requirements.txt>
```

Example, using the included vulnerable sample app:

```bash
python3 -m scanner.aggregator test_samples test_samples/requirements.txt
```

Note: run with `python3 -m scanner.aggregator`, not
`python3 scanner/aggregator.py` directly - the modules inside `scanner/`
import each other as a package, so `-m` is required or you'll get a
`ModuleNotFoundError`.

To save the JSON result to a file (timing logs go to stderr, so stdout
stays clean JSON):

```bash
python3 -m scanner.aggregator test_samples test_samples/requirements.txt > result.json
```

To also generate the user-facing reports:

```bash
mkdir -p audit-report
python3 -m scanner.aggregator test_samples test_samples/requirements.txt \
  --report-json audit-report/audit_report.json \
  --html audit-report/index.html \
  --markdown audit-report/summary.md \
  > audit-report/raw_scan_result.json
```

Open `audit-report/index.html` to browse findings, filter by severity/text,
and copy a safe prompt for another AI assistant.
In GitHub Actions, `summary.md` is also appended to the workflow summary so
the main findings are visible without downloading the artifact.

## Optional Gemini enrichment

The report generator works without an API key. If `GEMINI_API_KEY` is set,
the scanner asks Gemini to improve titles, summaries, risk explanations, and
fix guidance while preserving the same generic JSON schema. Only redacted
finding data is sent.

```bash
export GEMINI_API_KEY="..."
python3 -m scanner.aggregator . requirements.txt \
  --report-json audit-report/audit_report.json \
  --html audit-report/index.html
```

Use `--no-ai` to force deterministic local-only reports.
The workflow summary shows whether Gemini enrichment completed or whether the
local fallback was used. If Gemini fails, the API error is shown there.

## Project structure

```
ai-code-auditor/
├── scanner/
│   ├── __init__.py
│   ├── bandit_scan.py      # bandit wrapper
│   ├── secrets_scan.py     # detect-secrets wrapper
│   ├── deps_scan.py        # pip-audit wrapper
│   ├── aggregator.py       # runs all three concurrently, merges results
│   ├── ai_report.py        # optional Gemini enrichment + generic report schema
│   ├── html_report.py      # interactive artifact report
│   ├── markdown_report.py  # GitHub Actions summary report
│   └── redaction.py        # masks secrets before reports/cache/AI
├── test_samples/
│   ├── vulnerable_app.py   # intentionally vulnerable sample code
│   ├── requirements.txt    # intentionally outdated dependencies
│   └── .env                # sample secrets (for testing detect-secrets)
├── requirements.txt        # project dependencies (bandit, pip-audit, detect-secrets)
└── README.md
```

## GitHub Actions

The included `.github/workflows/security-scan.yml` runs on `push` to `master`
and on every pull request. It restores `.audit_cache.json`, runs the scan,
uploads `security-audit-report`, and then fails the job if any `HIGH`
severity findings exist.

To enable Gemini in CI, add a repository secret named `GEMINI_API_KEY`.
Forked pull requests will still get the deterministic report when that secret
is unavailable.

## Design notes

- **Unified finding format**: every finding from every tool shares the
  same fields (`severity`, `file`, `line`, `raw_description`, etc.),
  regardless of source. This is what will let the AI layer (stage 2,
  not yet built) treat all findings the same way.
- **Concurrent execution**: each tool runs in its own thread
  (`ThreadPoolExecutor`). This works well here because each tool
  spends most of its time waiting on a subprocess (I/O-bound), not
  doing CPU-bound work in Python itself - so the GIL isn't a
  bottleneck.
- **Secrets are redacted before reports/cache**: scanner output is passed
  through `scanner/redaction.py` so accidental values echoed by tools are
  masked before being written to JSON, HTML, cache, or sent to Gemini.
- **`--all-files` for detect-secrets**: without this flag, dotfiles
  like `.env` are silently skipped. Worth remembering if you add more
  scanners later.
