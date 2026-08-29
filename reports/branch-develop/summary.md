## Security audit report

**Total findings:** 37

| Severity | Count |
| --- | ---: |
| HIGH | 11 |
| MEDIUM | 12 |
| LOW | 14 |
| UNRATED | 0 |

**Cache:** scanned 22 changed file(s), skipped 0 unchanged file(s).

### Findings

| Severity | Tool | Location | Rule | Fix prompt |
| --- | --- | --- | --- | --- |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:27` | `B602` | Mitigate command injection risk (B602) in test_samples/vulnerable_app.py:27 by removing `shell=True` from `subprocess.Popen`. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:32` | `B324` | Upgrade weak MD5 hash (B324) in test_samples/vulnerable_app.py:32 to a stronger cryptographic algorithm for security purposes. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:49` | `B201` | Disable Flask debug mode (B201) in test_samples/vulnerable_app.py:49 for production deployments. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `base64_high_entropy_string` | Remove hardcoded high-entropy secret (base64_high_entropy_string) from test_samples/.env:2 and rotate it. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `secret_keyword` | Remove hardcoded secret keyword (secret_keyword) from test_samples/.env:2 and rotate it. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:14` | `aws_access_key` | Critical: Exposed AWS Access Key detected in `test_samples/vulnerable_app.py` at line 14. This credential must be removed, rotated, and managed securely to prevent unauthorized access. Refer to CWE-798 for guidance. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:15` | `secret_keyword` | Critical: Potential hardcoded secret keyword found in `test_samples/vulnerable_app.py` at line 15. Review and remove if it represents a credential; use a secret manager instead. Refer to CWE-798 for guidance. |
| ! HIGH | `semgrep` | `action.yml:52` | `yaml.github-actions.security.run-shell-injection.run-shell-injection` | High: GitHub Actions shell injection via untrusted `github` context in `action.yml` at line 52. Refactor `run:` step to use environment variables for `github` context data and ensure proper quoting. Refer to CWE-78 for... |
| ! HIGH | `semgrep` | `action.yml:101` | `yaml.github-actions.security.run-shell-injection.run-shell-injection` | High: GitHub Actions shell injection via untrusted `github` context in `action.yml` at line 101. Refactor `run:` step to use environment variables for `github` context data and ensure proper quoting. Refer to CWE-78 for... |
| ! HIGH | `semgrep` | `action.yml:121` | `yaml.github-actions.security.run-shell-injection.run-shell-injection` | High: GitHub Actions shell injection via untrusted `github` context in `action.yml` at line 121. Refactor `run:` step to use environment variables for `github` context data and ensure proper quoting. Refer to CWE-78 for... |
| ! HIGH | `semgrep` | `test_samples/.env:2` | `generic.secrets.security.detected-stripe-api-key.detected-stripe-api-key` | Secure a hardcoded Stripe API key found in `test_samples/.env` at line 2. This credential exposure could lead to unauthorized access and financial risks. Move the API key to a secure secret management solution. |
| ^ MEDIUM | `bandit` | `scanner/ai_report.py:201` | `B310` | Fix security finding B310: Insecure URL Scheme in `urllib.urlopen` in `scanner/ai_report.py` at line `201`. The `urllib.urlopen` function is used without proper scheme validation, which could allow arbitrary file access... |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:21` | `B608` | Resolve potential SQL injection (B608) in test_samples/vulnerable_app.py:21 by using parameterized queries. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:37` | `B506` | Remediate unsafe YAML deserialization (B506) in test_samples/vulnerable_app.py:37 by using `yaml.safe_load()`. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:44` | `B307` | Eliminate insecure `eval()` usage (B307) in test_samples/vulnerable_app.py:44; consider `ast.literal_eval()` or alternatives. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:49` | `B104` | Restrict application binding (B104) in test_samples/vulnerable_app.py:49 to specific interfaces instead of `0.0.0.0`. |
| ^ MEDIUM | `semgrep` | `.github/workflows/security-scan.yml:22` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Medium: GitHub Actions mutable tag found in `.github/workflows/security-scan.yml` at line 22. Update `uses:` to use a full commit SHA to prevent supply chain attacks. Refer to CWE-1357 for more details. |
| ^ MEDIUM | `semgrep` | `action.yml:75` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Medium: GitHub Actions mutable tag found in `action.yml` at line 75. Update `uses:` to use a full commit SHA to prevent supply chain attacks. Refer to CWE-1357 for more details. |
| ^ MEDIUM | `semgrep` | `action.yml:84` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Medium: GitHub Actions mutable tag found in `action.yml` at line 84. Update `uses:` to use a full commit SHA to prevent supply chain attacks. Refer to CWE-1357 for more details. |
| ^ MEDIUM | `semgrep` | `action.yml:112` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Medium: GitHub Actions mutable tag found in `action.yml` at line 112. Update `uses:` to use a full commit SHA to prevent supply chain attacks. Refer to CWE-1357 for more details. |
| ^ MEDIUM | `semgrep` | `action.yml:160` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Medium: GitHub Actions mutable tag found in `action.yml` at line 160. Update `uses:` to use a full commit SHA to prevent supply chain attacks. Refer to CWE-1357 for more details. |
| ^ MEDIUM | `semgrep` | `action.yml:176` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Medium: GitHub Actions mutable tag found in `action.yml` at line 176. Update `uses:` to use a full commit SHA to prevent supply chain attacks. Refer to CWE-1357 for more details. |
| ^ MEDIUM | `semgrep` | `action.yml:184` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Medium: GitHub Actions mutable tag found in `action.yml` at line 184. Update `uses:` to use a full commit SHA to prevent supply chain attacks. Refer to CWE-1357 for more details. |
| i LOW | `bandit` | `scanner/bandit_scan.py:9` | `B404` | Fix security finding B404: Unrestricted `subprocess` Module Import in `scanner/bandit_scan.py` at line `9`. The `subprocess` module import indicates potential for command execution vulnerabilities if not handled careful... |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B607` | Fix security finding B607: Insecure Execution of Process with Partial Path in `scanner/bandit_scan.py` at line `27`. A process is started using a partial executable path, which can be hijacked if the system's PATH is co... |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B603` | Fix security finding B603: Command Injection via `subprocess` Call with Untrusted Input in `scanner/bandit_scan.py` at line `27`. A `subprocess` call is made, and arguments should be checked for untrusted input to preve... |
| i LOW | `bandit` | `scanner/deps_scan.py:9` | `B404` | Fix security finding B404: Unrestricted `subprocess` Module Import in `scanner/deps_scan.py` at line `9`. The `subprocess` module import indicates potential for command execution vulnerabilities if not handled carefully. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B607` | Fix security finding B607: Insecure Execution of Process with Partial Path in `scanner/deps_scan.py` at line `13`. A process is started using a partial executable path, which can be hijacked if the system's PATH is comp... |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B603` | Fix security finding B603: Command Injection via `subprocess` Call with Untrusted Input in `scanner/deps_scan.py` at line `13`. A `subprocess` call is made, and arguments should be checked for untrusted input to prevent... |
| i LOW | `bandit` | `scanner/secrets_scan.py:10` | `B404` | Fix security finding B404: Unrestricted `subprocess` Module Import in `scanner/secrets_scan.py` at line `10`. The `subprocess` module import indicates potential for command execution vulnerabilities if not handled caref... |

_Showing the highest priority 30 findings. Download the HTML artifact for 7 more._


**AI:** Gemini enrichment completed.
