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
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:27` | `B602` | Fix B602 (Command Injection) in test_samples/vulnerable_app.py:27. Issue: `subprocess.Popen` with `shell=True` can lead to arbitrary command execution. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:32` | `B324` | Fix B324 (Weak Hash) in test_samples/vulnerable_app.py:32. Issue: MD5 is cryptographically weak and should not be used for security. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:49` | `B201` | Fix B201 (Debug Mode) in test_samples/vulnerable_app.py:49. Issue: Flask `debug=True` exposes the debugger, allowing RCE. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `base64_high_entropy_string` | Fix exposed secret (Base64 High Entropy String) in test_samples/.env:2. Issue: A potential secret was found in a `.env` file. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `secret_keyword` | Fix exposed secret (Secret Keyword) in test_samples/.env:2. Issue: A potential secret was found using a keyword match. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:14` | `aws_access_key` | Fix exposed secret (AWS Access Key) in test_samples/vulnerable_app.py:14. Issue: AWS Access Key hardcoded in source code. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:15` | `secret_keyword` | Fix exposed secret (Secret Keyword) in test_samples/vulnerable_app.py:15. Issue: A potential secret was found using a keyword match. |
| ^ MEDIUM | `bandit` | `scanner/ai_report.py:201` | `B310` | Fix security finding B310 in `scanner/ai_report.py:201`. Issue: Unsafe URL open call detected, which may be vulnerable to SSRF if the URL is untrusted. Validate URL schemes and hosts. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:21` | `B608` | Fix B608 (Potential SQL Injection) in test_samples/vulnerable_app.py:21. Issue: String-based SQL query construction can lead to injection vulnerabilities. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:37` | `B506` | Fix B506 (Unsafe YAML Deserialization) in test_samples/vulnerable_app.py:37. Issue: `yaml.load()` allows arbitrary object instantiation, risking RCE. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:44` | `B307` | Fix B307 (Insecure eval) in test_samples/vulnerable_app.py:44. Issue: `eval()` with untrusted input can lead to arbitrary code execution. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:49` | `B104` | Fix B104 (Bind All Interfaces) in test_samples/vulnerable_app.py:49. Issue: Server binds to '0.0.0.0', increasing exposure. |
| i LOW | `bandit` | `scanner/bandit_scan.py:9` | `B404` | Fix security finding B404 in `scanner/bandit_scan.py:9`. Issue: Unsafe import of `subprocess` module identified. Review its usage for potential command injection vulnerabilities. |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B607` | Fix security finding B607 in `scanner/bandit_scan.py:27`. Issue: A process is started with a partial executable path, posing a risk of path hijacking. |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B603` | Fix security finding B603 in `scanner/bandit_scan.py:27`. Issue: Subprocess call with potential for untrusted input. Ensure command arguments are a list of strings and sanitized. |
| i LOW | `bandit` | `scanner/deps_scan.py:9` | `B404` | Fix security finding B404 in `scanner/deps_scan.py:9`. Issue: Unsafe import of `subprocess` module identified. Review its usage for potential command injection vulnerabilities. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B607` | Fix security finding B607 in `scanner/deps_scan.py:13`. Issue: A process is started with a partial executable path, posing a risk of path hijacking. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B603` | Fix security finding B603 in `scanner/deps_scan.py:13`. Issue: Subprocess call with potential for untrusted input. Ensure command arguments are a list of strings and sanitized. |
| i LOW | `bandit` | `scanner/secrets_scan.py:10` | `B404` | Fix security finding B404 in `scanner/secrets_scan.py:10`. Issue: Unsafe import of `subprocess` module identified. Review its usage for potential command injection vulnerabilities. |
| i LOW | `bandit` | `scanner/secrets_scan.py:25` | `B607` | Fix security finding B607 in `scanner/secrets_scan.py:25`. Issue: A process is started with a partial executable path, posing a risk of path hijacking. |
| i LOW | `bandit` | `scanner/secrets_scan.py:25` | `B603` | Fix security finding B603 in `scanner/secrets_scan.py:25`. Issue: Subprocess call with potential for untrusted input. Ensure command arguments are a list of strings and sanitized. |
| i LOW | `bandit` | `test_samples/vulnerable_app.py:5` | `B404` | Fix security finding B404 in `test_samples/vulnerable_app.py:5`. Issue: Unsafe import of `subprocess` module identified. Review its usage for potential command injection vulnerabilities. |
| i LOW | `bandit` | `test_samples/vulnerable_app.py:15` | `B105` | Fix security finding B105 in `test_samples/vulnerable_app.py:15`. Issue: Hardcoded password detected. Remove sensitive credentials from the codebase and use a secure secrets management solution. |


**AI:** Gemini enrichment completed.
