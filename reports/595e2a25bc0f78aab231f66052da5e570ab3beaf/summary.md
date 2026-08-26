## Security audit report

**Total findings:** 23

| Severity | Count |
| --- | ---: |
| HIGH | 7 |
| MEDIUM | 5 |
| LOW | 11 |
| UNRATED | 0 |

**Cache:** scanned 20 changed file(s), skipped 0 unchanged file(s).

### Findings

| Severity | Tool | Location | Rule | Fix prompt |
| --- | --- | --- | --- | --- |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:27` | `B602` | Fix B602 in test_samples/vulnerable_app.py:27. Issue: `subprocess.Popen` used with `shell=True`. Refactor to pass command as a list to prevent command injection. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:32` | `B324` | Fix B324 in test_samples/vulnerable_app.py:32. Issue: MD5 hash used for security. Replace with a stronger algorithm like SHA-256 or a password hashing function. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:49` | `B201` | Fix B201 in test_samples/vulnerable_app.py:49. Issue: Flask debug mode enabled. Set `debug=False` for production to prevent arbitrary code execution via the debugger. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `base64_high_entropy_string` | Fix `base64_high_entropy_string` in test_samples/.env:2. Issue: Hardcoded Base64 secret. Revoke, remove from history, and use a secret manager. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `secret_keyword` | Fix `secret_keyword` in test_samples/.env:2. Issue: Hardcoded secret keyword detected. Revoke, remove from history, and use a secure secret management solution. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:14` | `aws_access_key` | Fix `aws_access_key` in test_samples/vulnerable_app.py:14. Issue: Hardcoded AWS Access Key. Revoke immediately, remove from history, and use IAM Roles or Secrets Manager. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:15` | `secret_keyword` | Fix `secret_keyword` in test_samples/vulnerable_app.py:15. Issue: Hardcoded secret keyword. Revoke, remove from history, and use secure secret management. |
| ^ MEDIUM | `bandit` | `scanner/ai_report.py:201` | `B310` | Fix security finding B310 in scanner/ai_report.py:201: Unsafe Use of urllib.urlopen with Potentially Malicious Schemes. Restrict allowed URL schemes to prevent SSRF/LFI. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:21` | `B608` | Fix B608 in test_samples/vulnerable_app.py:21. Issue: Potential SQL injection due to hardcoded SQL expressions. Use parameterized queries instead. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:37` | `B506` | Fix B506 in test_samples/vulnerable_app.py:37. Issue: Unsafe `yaml.load()` usage. Switch to `yaml.safe_load()` to prevent arbitrary object instantiation and potential RCE. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:44` | `B307` | Fix B307 in test_samples/vulnerable_app.py:44. Issue: Insecure use of `eval()`. Replace with `ast.literal_eval()` for safe evaluation of literal structures, or refactor to avoid dynamic code execution. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:49` | `B104` | Fix B104 in test_samples/vulnerable_app.py:49. Issue: Application binds to all network interfaces. Restrict binding to specific IP addresses to reduce attack surface. |
| i LOW | `bandit` | `scanner/bandit_scan.py:9` | `B404` | Fix security finding B404 in scanner/bandit_scan.py:9: Import of subprocess module for command execution. Review usage for command injection risks. |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B607` | Fix security finding B607 in scanner/bandit_scan.py:27: Process Started with Partial Executable Path. Use absolute paths to prevent PATH hijacking. |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B603` | Fix security finding B603 in scanner/bandit_scan.py:27: Subprocess Execution with Untrusted Input. Validate and escape all arguments from untrusted sources. |
| i LOW | `bandit` | `scanner/deps_scan.py:9` | `B404` | Fix security finding B404 in scanner/deps_scan.py:9: Import of subprocess module for command execution. Review usage for command injection risks. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B607` | Fix security finding B607 in scanner/deps_scan.py:13: Process Started with Partial Executable Path. Use absolute paths to prevent PATH hijacking. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B603` | Fix security finding B603 in scanner/deps_scan.py:13: Subprocess Execution with Untrusted Input. Validate and escape all arguments from untrusted sources. |
| i LOW | `bandit` | `scanner/secrets_scan.py:10` | `B404` | Fix security finding B404 in scanner/secrets_scan.py:10: Import of subprocess module for command execution. Review usage for command injection risks. |
| i LOW | `bandit` | `scanner/secrets_scan.py:25` | `B607` | Fix security finding B607 in scanner/secrets_scan.py:25: Process Started with Partial Executable Path. Use absolute paths to prevent PATH hijacking. |
| i LOW | `bandit` | `scanner/secrets_scan.py:25` | `B603` | Fix security finding B603 in scanner/secrets_scan.py:25: Subprocess Execution with Untrusted Input. Validate and escape all arguments from untrusted sources. |
| i LOW | `bandit` | `test_samples/vulnerable_app.py:5` | `B404` | Fix security finding B404 in test_samples/vulnerable_app.py:5: Import of subprocess module for command execution. Review usage for command injection risks. |
| i LOW | `bandit` | `test_samples/vulnerable_app.py:15` | `B105` | Fix security finding B105 in test_samples/vulnerable_app.py:15: Hardcoded Password String Detected. Remove hardcoded secret and use a secure secrets management solution. |


**AI:** Gemini enrichment completed.
