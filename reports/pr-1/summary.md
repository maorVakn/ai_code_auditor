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
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:27` | `B602` | Fix security finding B602 in test_samples/vulnerable_app.py:27. Issue: `subprocess.Popen` with `shell=True` creates command injection risk. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:32` | `B324` | Fix security finding B324 in test_samples/vulnerable_app.py:32. Issue: Weak MD5 hashing algorithm used for security-sensitive operation. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:49` | `B201` | Fix security finding B201 in test_samples/vulnerable_app.py:49. Issue: Flask app running with `debug=True` in production, exposing RCE. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `base64_high_entropy_string` | Fix security finding `base64_high_entropy_string` in `test_samples/.env:2`. Issue: High-entropy Base64 string indicating a possible exposed secret. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `secret_keyword` | Fix security finding `secret_keyword` in `test_samples/.env:2`. Issue: Secret keyword detected, indicating a possible exposed credential. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:14` | `aws_access_key` | Remove hardcoded AWS credentials from test_samples/vulnerable_app.py at line 14 and use a secure secret management solution. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:15` | `secret_keyword` | Refactor code at test_samples/vulnerable_app.py line 15 to remove hardcoded credential tokens. |
| ! HIGH | `semgrep` | `action.yml:52` | `yaml.github-actions.security.run-shell-injection.run-shell-injection` | Refactor action.yml line 52 to avoid direct shell interpolation of GitHub context data by using environment variables. |
| ! HIGH | `semgrep` | `action.yml:101` | `yaml.github-actions.security.run-shell-injection.run-shell-injection` | Implement environment variable mapping for inputs in action.yml at line 101 to prevent shell injection. |
| ! HIGH | `semgrep` | `action.yml:121` | `yaml.github-actions.security.run-shell-injection.run-shell-injection` | Mitigate shell injection risk in action.yml line 121 by using environment variables for shell input. |
| ! HIGH | `semgrep` | `test_samples/.env:2` | `generic.secrets.security.detected-stripe-api-key.detected-stripe-api-key` | Fix: Hardcoded Stripe API Key found in `test_samples/.env` at line 2. This key could lead to unauthorized access to your Stripe account. Remove the key from the file and use environment variables or a secrets management... |
| ^ MEDIUM | `bandit` | `scanner/ai_report.py:201` | `B310` | Fix security finding B310 in scanner/ai_report.py:201. Issue: Unsafe use of `urllib.urlopen` with potentially untrusted URL schemes can lead to SSRF or local file disclosure. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:21` | `B608` | Fix security finding B608 in test_samples/vulnerable_app.py:21. Issue: SQL query built with string concatenation, vulnerable to injection. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:37` | `B506` | Fix security finding B506 in test_samples/vulnerable_app.py:37. Issue: Unsafe `yaml.load()` detected, vulnerable to remote code execution. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:44` | `B307` | Fix security finding B307 in test_samples/vulnerable_app.py:44. Issue: Dangerous `eval()` function used, posing a code execution risk. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:49` | `B104` | Fix security finding B104 in test_samples/vulnerable_app.py:49. Issue: Application binds to all network interfaces, potentially exposing it. |
| ^ MEDIUM | `semgrep` | `.github/workflows/security-scan.yml:22` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Update the GitHub Action in .github/workflows/security-scan.yml at line 22 to use a full commit SHA instead of a mutable tag. |
| ^ MEDIUM | `semgrep` | `action.yml:75` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Pin the GitHub action used in action.yml line 75 to a permanent commit SHA. |
| ^ MEDIUM | `semgrep` | `action.yml:84` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Replace the mutable tag in action.yml line 84 with a static commit SHA. |
| ^ MEDIUM | `semgrep` | `action.yml:112` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Fix mutable GitHub action in action.yml at line 112 by pinning it to a fixed commit hash. |
| ^ MEDIUM | `semgrep` | `action.yml:160` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Update action.yml line 160 to reference an immutable commit SHA instead of a mutable tag. |
| ^ MEDIUM | `semgrep` | `action.yml:176` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Update action.yml line 176 by pinning the GitHub action to a commit SHA. |
| ^ MEDIUM | `semgrep` | `action.yml:184` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Change the mutable reference at action.yml line 184 to an immutable commit SHA. |
| i LOW | `bandit` | `scanner/bandit_scan.py:9` | `B404` | Fix security finding B404 in scanner/bandit_scan.py:9. Issue: `subprocess` module import identified, review its usage for potential command injection risks. |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B607` | Fix security finding B607 in scanner/bandit_scan.py:27. Issue: Executable specified with a partial path, risking path injection vulnerabilities. |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B603` | Fix security finding B603 in scanner/bandit_scan.py:27. Issue: Subprocess call may be vulnerable to command injection if input is not properly handled. |
| i LOW | `bandit` | `scanner/deps_scan.py:9` | `B404` | Fix security finding B404 in scanner/deps_scan.py:9. Issue: `subprocess` module import identified, review its usage for potential command injection risks. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B607` | Fix security finding B607 in scanner/deps_scan.py:13. Issue: Executable specified with a partial path, risking path injection vulnerabilities. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B603` | Fix security finding B603 in scanner/deps_scan.py:13. Issue: Subprocess call may be vulnerable to command injection if input is not properly handled. |
| i LOW | `bandit` | `scanner/secrets_scan.py:10` | `B404` | Fix security finding B404 in scanner/secrets_scan.py:10. Issue: `subprocess` module import identified, review its usage for potential command injection risks. |

_Showing the highest priority 30 findings. Download the HTML artifact for 7 more._


**AI:** Gemini enrichment completed.
