# AI Code Security Auditor

A Python tool that scans a code repository for security issues, then uses
Claude to explain each finding, rate its severity, and suggest a fix.

Currently implemented: **Stage 1 - static scanning**. Three tools run
concurrently (separate threads) and their output is merged into one
unified finding format:

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

## Project structure

```
ai-code-auditor/
├── scanner/
│   ├── __init__.py
│   ├── bandit_scan.py      # bandit wrapper
│   ├── secrets_scan.py     # detect-secrets wrapper
│   ├── deps_scan.py        # pip-audit wrapper
│   └── aggregator.py       # runs all three concurrently, merges results
├── test_samples/
│   ├── vulnerable_app.py   # intentionally vulnerable sample code
│   ├── requirements.txt    # intentionally outdated dependencies
│   └── .env                # sample secrets (for testing detect-secrets)
├── requirements.txt        # project dependencies (bandit, pip-audit, detect-secrets)
└── README.md
```

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
- **Secrets are never stored in the output**: `secrets_scan.py`
  intentionally sets `code_snippet: null` for exposed secrets, so the
  actual credential value is never written to disk or later sent to
  an external API.
- **`--all-files` for detect-secrets**: without this flag, dotfiles
  like `.env` are silently skipped. Worth remembering if you add more
  scanners later.
