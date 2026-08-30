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
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:27` | `B602` | Mitigate critical command injection (B602) in test_samples/vulnerable_app.py:27. Issue: `subprocess.Popen` used with `shell=True`, posing a severe risk. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:32` | `B324` | Upgrade hashing algorithm (B324) in test_samples/vulnerable_app.py:32. Issue: Weak MD5 hash detected; consider stronger alternatives like SHA-256. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:49` | `B201` | Disable Flask debug mode (B201) in test_samples/vulnerable_app.py:49. Issue: Flask app running with `debug=True`, exposing arbitrary code execution vulnerability. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `base64_high_entropy_string` | Remove exposed Base64 secret (base64_high_entropy_string) from test_samples/.env:2. Issue: High-entropy string likely representing a sensitive credential committed. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `secret_keyword` | Remove exposed keyword-based secret (secret_keyword) from test_samples/.env:2. Issue: Sensitive credential identified by keyword in committed environment file. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:14` | `aws_access_key` | Remove hardcoded AWS credentials from test_samples/vulnerable_app.py:14 and implement secure secret management. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:15` | `secret_keyword` | Refactor code at test_samples/vulnerable_app.py:15 to remove hardcoded secret keywords. |
| ! HIGH | `semgrep` | `action.yml:52` | `yaml.github-actions.security.run-shell-injection.run-shell-injection` | Remediate shell injection at action.yml:52 by using environment variables for dynamic workflow inputs. |
| ! HIGH | `semgrep` | `action.yml:101` | `yaml.github-actions.security.run-shell-injection.run-shell-injection` | Remediate shell injection at action.yml:101 by using environment variables for dynamic workflow inputs. |
| ! HIGH | `semgrep` | `action.yml:121` | `yaml.github-actions.security.run-shell-injection.run-shell-injection` | Remediate shell injection at action.yml:121 by using environment variables for dynamic workflow inputs. |
| ! HIGH | `semgrep` | `test_samples/.env:2` | `generic.secrets.security.detected-stripe-api-key.detected-stripe-api-key` | Remediate hardcoded Stripe API key in `test_samples/.env` at line 2. The Stripe API key should be moved to a secure environment variable or a secrets management system to prevent unauthorized access and potential compro... |
| ^ MEDIUM | `bandit` | `scanner/ai_report.py:201` | `B310` | Fix Insecure URL Scheme (B310) in `scanner/ai_report.py:201`. The `urlopen` call lacks scheme validation, posing a risk of arbitrary file access or unintended behavior through malicious URLs. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:21` | `B608` | Remediate SQL injection vulnerability (B608) in test_samples/vulnerable_app.py:21. Issue: SQL queries constructed using insecure string concatenation. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:37` | `B506` | Resolve unsafe YAML deserialization (B506) in test_samples/vulnerable_app.py:37. Issue: `yaml.load()` used, enabling arbitrary object instantiation from untrusted input. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:44` | `B307` | Eliminate insecure `eval()` usage (B307) in test_samples/vulnerable_app.py:44. Issue: `eval()` found, posing a severe code execution risk. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:49` | `B104` | Restrict network interface binding (B104) in test_samples/vulnerable_app.py:49. Issue: Application binds to all interfaces, potentially overexposing it. |
| ^ MEDIUM | `semgrep` | `.github/workflows/security-scan.yml:22` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Update the GitHub action at .github/workflows/security-scan.yml:22 to use a fixed commit SHA for security hardening. |
| ^ MEDIUM | `semgrep` | `action.yml:75` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Update the GitHub action at action.yml:75 to use a fixed commit SHA for security hardening. |
| ^ MEDIUM | `semgrep` | `action.yml:84` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Update the GitHub action at action.yml:84 to use a fixed commit SHA for security hardening. |
| ^ MEDIUM | `semgrep` | `action.yml:112` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Update the GitHub action at action.yml:112 to use a fixed commit SHA for security hardening. |
| ^ MEDIUM | `semgrep` | `action.yml:160` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Update the GitHub action at action.yml:160 to use a fixed commit SHA for security hardening. |
| ^ MEDIUM | `semgrep` | `action.yml:176` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Update the GitHub action at action.yml:176 to use a fixed commit SHA for security hardening. |
| ^ MEDIUM | `semgrep` | `action.yml:184` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Update the GitHub action at action.yml:184 to use a fixed commit SHA for security hardening. |
| i LOW | `bandit` | `scanner/bandit_scan.py:9` | `B404` | Address Unrestricted Use of subprocess (B404) in `scanner/bandit_scan.py:9`. The `subprocess` module can introduce command injection risks if not handled with care, particularly with untrusted input. |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B607` | Resolve Process Started with Partial Executable Path (B607) in `scanner/bandit_scan.py:27`. Using partial paths can allow `PATH` manipulation to execute unintended programs. |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B603` | Patch Potential Command Injection in subprocess Call (B603) in `scanner/bandit_scan.py:27`. Untrusted input in `subprocess` arguments can lead to command injection. |
| i LOW | `bandit` | `scanner/deps_scan.py:9` | `B404` | Address Unrestricted Use of subprocess (B404) in `scanner/deps_scan.py:9`. The `subprocess` module can introduce command injection risks if not handled with care, particularly with untrusted input. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B607` | Resolve Process Started with Partial Executable Path (B607) in `scanner/deps_scan.py:13`. Using partial paths can allow `PATH` manipulation to execute unintended programs. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B603` | Patch Potential Command Injection in subprocess Call (B603) in `scanner/deps_scan.py:13`. Untrusted input in `subprocess` arguments can lead to command injection. |
| i LOW | `bandit` | `scanner/secrets_scan.py:10` | `B404` | Address Unrestricted Use of subprocess (B404) in `scanner/secrets_scan.py:10`. The `subprocess` module can introduce command injection risks if not handled with care, particularly with untrusted input. |

_Showing the highest priority 30 findings. Download the HTML artifact for 7 more._


**AI:** Gemini enrichment completed.
