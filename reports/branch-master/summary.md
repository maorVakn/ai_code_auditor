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
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:27` | `B602` | Fix security finding B602 in test_samples/vulnerable_app.py:27. Issue: Subprocess call with shell=True enables arbitrary command execution. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:32` | `B324` | Fix security finding B324 in test_samples/vulnerable_app.py:32. Issue: Weak MD5 hash used for security, risking cryptographic compromise. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:49` | `B201` | Fix security finding B201 in test_samples/vulnerable_app.py:49. Issue: Flask debug mode is enabled, exposing the Werkzeug debugger and allowing arbitrary code execution. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `base64_high_entropy_string` | Fix security finding `base64_high_entropy_string` in test_samples/.env:2. Issue: Hardcoded Base64 high-entropy string, possibly an exposed secret. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `secret_keyword` | Fix security finding `secret_keyword` in test_samples/.env:2. Issue: Hardcoded 'secret keyword' credential detected, indicating an exposed secret. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:14` | `aws_access_key` | Fix security finding `aws_access_key` in test_samples/vulnerable_app.py:14. Issue: Hardcoded AWS Access Key found, posing a critical security risk. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:15` | `secret_keyword` | Fix security finding `secret_keyword` in test_samples/vulnerable_app.py:15. Issue: Hardcoded 'secret keyword' string in code, indicating an exposed secret. |
| ^ MEDIUM | `bandit` | `scanner/ai_report.py:201` | `B310` | Fix security finding B310: Unsafe URL Scheme in `urllib.urlopen` in `scanner/ai_report.py` at line 201. The `urllib.urlopen` function should be audited for permitted schemes to prevent exploitation via `file:/` or custo... |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:21` | `B608` | Fix security finding B608 in test_samples/vulnerable_app.py:21. Issue: Hardcoded SQL expressions create a potential SQL injection vulnerability. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:37` | `B506` | Fix security finding B506 in test_samples/vulnerable_app.py:37. Issue: Unsafe `yaml.load()` permits arbitrary object instantiation and code execution. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:44` | `B307` | Fix security finding B307 in test_samples/vulnerable_app.py:44. Issue: Insecure `eval()` function usage can lead to arbitrary code execution. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:49` | `B104` | Fix security finding B104 in test_samples/vulnerable_app.py:49. Issue: Application binds to all network interfaces, potentially increasing attack surface. |
| i LOW | `bandit` | `scanner/bandit_scan.py:9` | `B404` | Fix security finding B404: Direct Use of `subprocess` Module in `scanner/bandit_scan.py` at line 9. Review `subprocess` module usage for potential command injection vulnerabilities, especially with untrusted input. |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B607` | Fix security finding B607: Execution of Process with Partial Executable Path in `scanner/bandit_scan.py` at line 27. Use absolute paths for executables to prevent PATH hijacking. |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B603` | Fix security finding B603: Subprocess Call with Untrusted Input and `shell=False` in `scanner/bandit_scan.py` at line 27. Validate and sanitize all untrusted input passed to subprocess calls, even when `shell=False`. |
| i LOW | `bandit` | `scanner/deps_scan.py:9` | `B404` | Fix security finding B404: Direct Use of `subprocess` Module in `scanner/deps_scan.py` at line 9. Review `subprocess` module usage for potential command injection vulnerabilities, especially with untrusted input. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B607` | Fix security finding B607: Execution of Process with Partial Executable Path in `scanner/deps_scan.py` at line 13. Use absolute paths for executables to prevent PATH hijacking. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B603` | Fix security finding B603: Subprocess Call with Untrusted Input and `shell=False` in `scanner/deps_scan.py` at line 13. Validate and sanitize all untrusted input passed to subprocess calls, even when `shell=False`. |
| i LOW | `bandit` | `scanner/secrets_scan.py:10` | `B404` | Fix security finding B404: Direct Use of `subprocess` Module in `scanner/secrets_scan.py` at line 10. Review `subprocess` module usage for potential command injection vulnerabilities, especially with untrusted input. |
| i LOW | `bandit` | `scanner/secrets_scan.py:25` | `B607` | Fix security finding B607: Execution of Process with Partial Executable Path in `scanner/secrets_scan.py` at line 25. Use absolute paths for executables to prevent PATH hijacking. |
| i LOW | `bandit` | `scanner/secrets_scan.py:25` | `B603` | Fix security finding B603: Subprocess Call with Untrusted Input and `shell=False` in `scanner/secrets_scan.py` at line 25. Validate and sanitize all untrusted input passed to subprocess calls, even when `shell=False`. |
| i LOW | `bandit` | `test_samples/vulnerable_app.py:5` | `B404` | Fix security finding B404: Direct Use of `subprocess` Module in `test_samples/vulnerable_app.py` at line 5. Review `subprocess` module usage for potential command injection vulnerabilities, especially with untrusted inp... |
| i LOW | `bandit` | `test_samples/vulnerable_app.py:15` | `B105` | Fix security finding B105: Hardcoded Password String Found in `test_samples/vulnerable_app.py` at line 15. Remove the hardcoded password and use a secure secrets management solution. |


**AI:** Gemini enrichment completed.
