## Security audit report

**Total findings:** 37

| Severity | Count |
| --- | ---: |
| HIGH | 11 |
| MEDIUM | 12 |
| LOW | 14 |
| UNRATED | 0 |

**Cache:** scanned 24 changed file(s), skipped 0 unchanged file(s).

### Findings

| Severity | Tool | Location | Rule | Fix prompt |
| --- | --- | --- | --- | --- |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:27` | `B602` | Fix security finding B602 in `test_samples/vulnerable_app.py:27`. Issue: `subprocess.Popen` used with `shell=True`, posing a high risk of command injection. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:32` | `B324` | Fix security finding B324 in `test_samples/vulnerable_app.py:32`. Issue: Weak MD5 hashing algorithm is used for security, risking collision attacks and data compromise. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:49` | `B201` | Fix security finding B201 in `test_samples/vulnerable_app.py:49`. Issue: Flask app running with `debug=True` in production exposes arbitrary code execution via Werkzeug debugger. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `base64_high_entropy_string` | Fix security finding `base64_high_entropy_string` in `test_samples/.env:2`. Issue: A Base64 encoded high-entropy string, potentially a sensitive secret, is exposed in the `.env` file. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `secret_keyword` | Fix security finding `secret_keyword` in `test_samples/.env:2`. Issue: A sensitive keyword in the `.env` file indicates an exposed secret, risking unauthorized access. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:14` | `aws_access_key` | Fix high-severity exposed secret (AWS Access Key) in test_samples/vulnerable_app.py:14. An AWS Access Key was found hardcoded, posing a risk of unauthorized cloud resource access. Remove, rotate, and use a secret manage... |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:15` | `secret_keyword` | Fix high-severity exposed secret (Secret Keyword) in test_samples/vulnerable_app.py:15. A potential secret keyword was found, risking unauthorized access. Remove, rotate if applicable, and secure using secret management. |
| ! HIGH | `semgrep` | `action.yml:52` | `yaml.github-actions.security.run-shell-injection.run-shell-injection` | Fix high-severity GitHub Actions shell injection in action.yml:52. Direct use of `github` context data in a `run` step risks shell injection. Use an intermediate, double-quoted environment variable. |
| ! HIGH | `semgrep` | `action.yml:101` | `yaml.github-actions.security.run-shell-injection.run-shell-injection` | Fix high-severity GitHub Actions shell injection in action.yml:101. Direct use of `github` context data in a `run` step risks shell injection. Use an intermediate, double-quoted environment variable. |
| ! HIGH | `semgrep` | `action.yml:121` | `yaml.github-actions.security.run-shell-injection.run-shell-injection` | Fix high-severity GitHub Actions shell injection in action.yml:121. Direct use of `github` context data in a `run` step risks shell injection. Use an intermediate, double-quoted environment variable. |
| ! HIGH | `semgrep` | `test_samples/.env:2` | `generic.secrets.security.detected-stripe-api-key.detected-stripe-api-key` | Address the critical security finding: A hardcoded Stripe API key was detected in `test_samples/.env` at line 2. This finding indicates a high-risk exposure of sensitive credentials that could lead to unauthorized acces... |
| ^ MEDIUM | `bandit` | `scanner/ai_report.py:201` | `B310` | Fix security finding B310 (Insecure URL Scheme in `urllib.urlopen`) in `scanner/ai_report.py:201`. The application uses `urllib.urlopen` which may permit insecure URL schemes, potentially leading to local file access or... |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:21` | `B608` | Fix security finding B608 in `test_samples/vulnerable_app.py:21`. Issue: SQL query built via string concatenation could lead to SQL injection if user input is incorporated. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:37` | `B506` | Fix security finding B506 in `test_samples/vulnerable_app.py:37`. Issue: Unsafe `yaml.load()` can lead to arbitrary code execution if parsing untrusted data. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:44` | `B307` | Fix security finding B307 in `test_samples/vulnerable_app.py:44`. Issue: Unsafe `eval()` function usage exposes the application to remote code execution from untrusted input. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:49` | `B104` | Fix security finding B104 in `test_samples/vulnerable_app.py:49`. Issue: Application binds to all network interfaces (`0.0.0.0`), potentially exposing it to unintended external access. |
| ^ MEDIUM | `semgrep` | `.github/workflows/security-scan.yml:22` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Fix medium-severity GitHub Actions mutable action tag in .github/workflows/security-scan.yml:22. A mutable action reference was found, posing a supply-chain risk. Pin to a full 40-character commit SHA. |
| ^ MEDIUM | `semgrep` | `action.yml:75` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Fix medium-severity GitHub Actions mutable action tag in action.yml:75. A mutable action reference was found, posing a supply-chain risk. Pin to a full 40-character commit SHA. |
| ^ MEDIUM | `semgrep` | `action.yml:84` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Fix medium-severity GitHub Actions mutable action tag in action.yml:84. A mutable action reference was found, posing a supply-chain risk. Pin to a full 40-character commit SHA. |
| ^ MEDIUM | `semgrep` | `action.yml:112` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Fix medium-severity GitHub Actions mutable action tag in action.yml:112. A mutable action reference was found, posing a supply-chain risk. Pin to a full 40-character commit SHA. |
| ^ MEDIUM | `semgrep` | `action.yml:160` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Fix medium-severity GitHub Actions mutable action tag in action.yml:160. A mutable action reference was found, posing a supply-chain risk. Pin to a full 40-character commit SHA. |
| ^ MEDIUM | `semgrep` | `action.yml:176` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Fix medium-severity GitHub Actions mutable action tag in action.yml:176. A mutable action reference was found, posing a supply-chain risk. Pin to a full 40-character commit SHA. |
| ^ MEDIUM | `semgrep` | `action.yml:184` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Fix medium-severity GitHub Actions mutable action tag in action.yml:184. A mutable action reference was found, posing a supply-chain risk. Pin to a full 40-character commit SHA. |
| i LOW | `bandit` | `scanner/bandit_scan.py:9` | `B404` | Fix security finding B404 (Potential Command Injection via `subprocess` Module Import) in `scanner/bandit_scan.py:9`. The application imports the `subprocess` module, which can pose security risks if used to execute ext... |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B607` | Fix security finding B607 (Process Started with Partial Executable Path) in `scanner/bandit_scan.py:27`. The application starts a process using a partial executable path, which could allow an attacker to execute malicio... |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B603` | Fix security finding B603 (Subprocess Call With Untrusted Input in Arguments) in `scanner/bandit_scan.py:27`. The application makes a `subprocess` call where untrusted input might be used in command arguments, potential... |
| i LOW | `bandit` | `scanner/deps_scan.py:9` | `B404` | Fix security finding B404 (Potential Command Injection via `subprocess` Module Import in Dependency Scanner) in `scanner/deps_scan.py:9`. The `subprocess` module is imported, presenting potential command injection risks... |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B607` | Fix security finding B607 (Process Execution with Relative Path in Dependency Scanner) in `scanner/deps_scan.py:13`. The application executes a process using a partial path, which could be exploited through PATH manipul... |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B603` | Fix security finding B603 (Unvalidated Input in `subprocess` Arguments in Dependency Scanner) in `scanner/deps_scan.py:13`. A `subprocess` call may use untrusted input as arguments, posing a risk of command injection. |
| i LOW | `bandit` | `scanner/secrets_scan.py:10` | `B404` | Fix security finding B404 (Potential Command Injection via `subprocess` Module Import in Secrets Scanner) in `scanner/secrets_scan.py:10`. The `subprocess` module is imported, which, if misused, could lead to command in... |

_Showing the highest priority 30 findings. Download the HTML artifact for 7 more._


**AI:** Gemini enrichment completed.
