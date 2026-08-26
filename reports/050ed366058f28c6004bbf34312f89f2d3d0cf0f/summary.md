## Security audit report

**Total findings:** 23

| Severity | Count |
| --- | ---: |
| HIGH | 7 |
| MEDIUM | 5 |
| LOW | 11 |
| UNRATED | 0 |

**Cache:** scanned 21 changed file(s), skipped 0 unchanged file(s).

### Findings

| Severity | Tool | Location | Rule | Fix prompt |
| --- | --- | --- | --- | --- |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:27` | `B602` | Address command injection vulnerability by avoiding `shell=True` in `subprocess.Popen` (B602) in test_samples/vulnerable_app.py:27. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:32` | `B324` | Upgrade to a stronger hashing algorithm like SHA-256/SHA-3 instead of MD5 (B324) in test_samples/vulnerable_app.py:32. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:49` | `B201` | Disable Flask debug mode (`debug=False`) for production environments (B201) in test_samples/vulnerable_app.py:49. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `base64_high_entropy_string` | Remove and rotate the exposed Base64 secret from test_samples/.env:2 (base64_high_entropy_string). |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `secret_keyword` | Remove and rotate the sensitive keyword secret from test_samples/.env:2 (secret_keyword). |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:14` | `aws_access_key` | Remove and rotate the exposed AWS Access Key from test_samples/vulnerable_app.py:14 (aws_access_key). |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:15` | `secret_keyword` | Remove and rotate the sensitive keyword secret from test_samples/vulnerable_app.py:15 (secret_keyword). |
| ^ MEDIUM | `bandit` | `scanner/ai_report.py:201` | `B310` | Fix B310: Restrict URL schemes in `urllib.urlopen` to prevent local file access in `scanner/ai_report.py:201`. Validate input URLs to only allow safe schemes. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:21` | `B608` | Refactor SQL query construction to use parameterized queries to prevent SQL injection (B608) in test_samples/vulnerable_app.py:21. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:37` | `B506` | Replace `yaml.load()` with `yaml.safe_load()` to prevent unsafe deserialization (B506) in test_samples/vulnerable_app.py:37. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:44` | `B307` | Replace `eval()` with `ast.literal_eval()` to prevent code execution vulnerability (B307) in test_samples/vulnerable_app.py:44. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:49` | `B104` | Limit application binding to specific network interfaces instead of all (B104) in test_samples/vulnerable_app.py:49. |
| i LOW | `bandit` | `scanner/bandit_scan.py:9` | `B404` | Fix B404: Address potential `subprocess` module misuse in `scanner/bandit_scan.py:9`. Review all `subprocess` calls and sanitize user input to prevent command injection. |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B607` | Fix B607: Use absolute paths for executables in `subprocess` calls in `scanner/bandit_scan.py:27` to prevent PATH hijacking vulnerabilities. |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B603` | Fix B603: Sanitize input for `subprocess` call in `scanner/bandit_scan.py:27` to prevent command injection, even without `shell=True`. |
| i LOW | `bandit` | `scanner/deps_scan.py:9` | `B404` | Fix B404: Address potential `subprocess` module misuse in `scanner/deps_scan.py:9`. Review all `subprocess` calls and sanitize user input to prevent command injection. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B607` | Fix B607: Use absolute paths for executables in `subprocess` calls in `scanner/deps_scan.py:13` to prevent PATH hijacking vulnerabilities. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B603` | Fix B603: Sanitize input for `subprocess` call in `scanner/deps_scan.py:13` to prevent command injection, even without `shell=True`. |
| i LOW | `bandit` | `scanner/secrets_scan.py:10` | `B404` | Fix B404: Address potential `subprocess` module misuse in `scanner/secrets_scan.py:10`. Review all `subprocess` calls and sanitize user input to prevent command injection. |
| i LOW | `bandit` | `scanner/secrets_scan.py:25` | `B607` | Fix B607: Use absolute paths for executables in `subprocess` calls in `scanner/secrets_scan.py:25` to prevent PATH hijacking vulnerabilities. |
| i LOW | `bandit` | `scanner/secrets_scan.py:25` | `B603` | Fix B603: Sanitize input for `subprocess` call in `scanner/secrets_scan.py:25` to prevent command injection, even without `shell=True`. |
| i LOW | `bandit` | `test_samples/vulnerable_app.py:5` | `B404` | Fix B404: Address potential `subprocess` module misuse in `test_samples/vulnerable_app.py:5`. Review all `subprocess` calls and sanitize user input to prevent command injection. |
| i LOW | `bandit` | `test_samples/vulnerable_app.py:15` | `B105` | Fix B105: Remove hardcoded password '[REDACTED_SECRET]' in `test_samples/vulnerable_app.py:15`. Implement secure credential management practices. |


**AI:** Gemini enrichment completed.
