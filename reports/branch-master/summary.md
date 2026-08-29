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
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:27` | `B602` | Fix B602: Critical Command Injection in `subprocess.Popen` with `shell=True` at `test_samples/vulnerable_app.py:27`. Refactor to avoid `shell=True`. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:32` | `B324` | Fix B324: Replace weak MD5 hash at `test_samples/vulnerable_app.py:32` with a stronger algorithm like SHA-256. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:49` | `B201` | Fix B201: Disable Flask debug mode (`debug=False`) at `test_samples/vulnerable_app.py:49` for production environments. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `base64_high_entropy_string` | Fix `base64_high_entropy_string`: Remove exposed secret from `test_samples/.env:2`. Rotate credential and use secure secret management. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `secret_keyword` | Fix `secret_keyword`: Remove exposed secret at `test_samples/.env:2`. Rotate credential and use secure secret management. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:14` | `aws_access_key` | Remediate hardcoded AWS Access Key in `test_samples/vulnerable_app.py` at line 14. Action required: Remove, rotate, and secure this credential. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:15` | `secret_keyword` | Remediate hardcoded 'Secret Keyword' in `test_samples/vulnerable_app.py` at line 15. Action required: Remove, rotate, and secure this credential. |
| ! HIGH | `semgrep` | `action.yml:52` | `yaml.github-actions.security.run-shell-injection.run-shell-injection` | Remediate GitHub Actions shell injection in `action.yml` at line 52. Use intermediate environment variables for `github` context data in `run` steps. |
| ! HIGH | `semgrep` | `action.yml:101` | `yaml.github-actions.security.run-shell-injection.run-shell-injection` | Remediate GitHub Actions shell injection in `action.yml` at line 101. Use intermediate environment variables for `github` context data in `run` steps. |
| ! HIGH | `semgrep` | `action.yml:121` | `yaml.github-actions.security.run-shell-injection.run-shell-injection` | Remediate GitHub Actions shell injection in `action.yml` at line 121. Use intermediate environment variables for `github` context data in `run` steps. |
| ! HIGH | `semgrep` | `test_samples/.env:2` | `generic.secrets.security.detected-stripe-api-key.detected-stripe-api-key` | Prompt: Fix the hardcoded Stripe API key detected in `test_samples/.env` at line 2. Replace the key with a reference to a secure environment variable or a secret management solution to prevent direct exposure. |
| ^ MEDIUM | `bandit` | `scanner/ai_report.py:201` | `B310` | Fix security finding B310 in scanner/ai_report.py:201. Issue: Unsafe URL scheme handling with `urllib.urlopen`. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:21` | `B608` | Fix B608: Address potential SQL injection at `test_samples/vulnerable_app.py:21`. Implement parameterized queries. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:37` | `B506` | Fix B506: Address unsafe YAML deserialization at `test_samples/vulnerable_app.py:37`. Use `yaml.safe_load()`. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:44` | `B307` | Fix B307: Address insecure `eval()` usage at `test_samples/vulnerable_app.py:44`. Consider `ast.literal_eval()` or safer alternatives. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:49` | `B104` | Fix B104: Restrict application binding to specific network interfaces at `test_samples/vulnerable_app.py:49` to reduce attack surface. |
| ^ MEDIUM | `semgrep` | `.github/workflows/security-scan.yml:22` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Address mutable GitHub Action reference in `.github/workflows/security-scan.yml` at line 22. Pin the action to a full commit SHA to prevent supply-chain attacks. |
| ^ MEDIUM | `semgrep` | `action.yml:75` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Address mutable GitHub Action reference in `action.yml` at line 75. Pin the action to a full commit SHA to prevent supply-chain attacks. |
| ^ MEDIUM | `semgrep` | `action.yml:84` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Address mutable GitHub Action reference in `action.yml` at line 84. Pin the action to a full commit SHA to prevent supply-chain attacks. |
| ^ MEDIUM | `semgrep` | `action.yml:112` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Address mutable GitHub Action reference in `action.yml` at line 112. Pin the action to a full commit SHA to prevent supply-chain attacks. |
| ^ MEDIUM | `semgrep` | `action.yml:160` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Address mutable GitHub Action reference in `action.yml` at line 160. Pin the action to a full commit SHA to prevent supply-chain attacks. |
| ^ MEDIUM | `semgrep` | `action.yml:176` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Address mutable GitHub Action reference in `action.yml` at line 176. Pin the action to a full commit SHA to prevent supply-chain attacks. |
| ^ MEDIUM | `semgrep` | `action.yml:184` | `yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag` | Address mutable GitHub Action reference in `action.yml` at line 184. Pin the action to a full commit SHA to prevent supply-chain attacks. |
| i LOW | `bandit` | `scanner/bandit_scan.py:9` | `B404` | Fix security finding B404 in scanner/bandit_scan.py:9. Issue: `subprocess` module import, review for command injection risks. |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B607` | Fix security finding B607 in scanner/bandit_scan.py:27. Issue: External command execution with partial path. |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B603` | Fix security finding B603 in scanner/bandit_scan.py:27. Issue: `subprocess` call with potential for argument injection. |
| i LOW | `bandit` | `scanner/deps_scan.py:9` | `B404` | Fix security finding B404 in scanner/deps_scan.py:9. Issue: `subprocess` module import, review for command injection risks. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B607` | Fix security finding B607 in scanner/deps_scan.py:13. Issue: External command execution with partial path. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B603` | Fix security finding B603 in scanner/deps_scan.py:13. Issue: `subprocess` call with potential for argument injection. |
| i LOW | `bandit` | `scanner/secrets_scan.py:10` | `B404` | Fix security finding B404 in scanner/secrets_scan.py:10. Issue: `subprocess` module import, review for command injection risks. |

_Showing the highest priority 30 findings. Download the HTML artifact for 7 more._


**AI:** Gemini enrichment completed.
