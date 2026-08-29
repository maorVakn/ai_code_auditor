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
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:27` | `B602` | Fix security finding B602 in test_samples/vulnerable_app.py:27. Issue: Shell injection risk; refactor subprocess to pass arguments as a list. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:32` | `B324` | Fix security finding B324 in test_samples/vulnerable_app.py:32. Issue: Insecure use of MD5; upgrade to a stronger hashing algorithm. |
| ! HIGH | `bandit` | `test_samples/vulnerable_app.py:49` | `B201` | Fix security finding B201 in test_samples/vulnerable_app.py:49. Issue: Flask debug mode is enabled; set to False for production environments. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `base64_high_entropy_string` | Fix security finding base64_high_entropy_string in test_samples/.env:2. Issue: Exposed high-entropy secret; remove from version control and rotate. |
| ! HIGH | `detect-secrets` | `test_samples/.env:2` | `secret_keyword` | Fix security finding secret_keyword in test_samples/.env:2. Issue: Potential secret detected via keyword; rotate and remove from repository. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:14` | `aws_access_key` | Fix security finding aws_access_key in test_samples/vulnerable_app.py:14. Issue: Hardcoded AWS key; revoke, remove from source, and use IAM roles. |
| ! HIGH | `detect-secrets` | `test_samples/vulnerable_app.py:15` | `secret_keyword` | Fix security finding secret_keyword in test_samples/vulnerable_app.py:15. Issue: Potential hardcoded secret; remove from code and move to a secure secret store. |
| ^ MEDIUM | `bandit` | `scanner/ai_report.py:201` | `B310` | Fix security finding B310 in scanner/ai_report.py:201. Issue: Unsafe URL scheme handling in `urllib.urlopen` could allow arbitrary file access or resource loading. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:21` | `B608` | Fix security finding B608 in test_samples/vulnerable_app.py:21. Issue: SQL injection risk due to string-based SQL construction; replace with parameterized queries. |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:37` | `B506` | Fix security finding B506 in test_samples/vulnerable_app.py:37. Issue: Unsafe YAML deserialization; replace yaml.load() with yaml.safe_load(). |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:44` | `B307` | Fix security finding B307 in test_samples/vulnerable_app.py:44. Issue: Arbitrary code execution risk from eval(); refactor to use ast.literal_eval(). |
| ^ MEDIUM | `bandit` | `test_samples/vulnerable_app.py:49` | `B104` | Fix security finding B104 in test_samples/vulnerable_app.py:49. Issue: Service binds to 0.0.0.0; restrict binding to localhost. |
| i LOW | `bandit` | `scanner/bandit_scan.py:9` | `B404` | Fix security finding B404 in scanner/bandit_scan.py:9. Issue: Potential command injection risk due to `subprocess` module import. |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B607` | Fix security finding B607 in scanner/bandit_scan.py:27. Issue: Process started with partial executable path, risking execution of unintended programs. |
| i LOW | `bandit` | `scanner/bandit_scan.py:27` | `B603` | Fix security finding B603 in scanner/bandit_scan.py:27. Issue: `subprocess` call with untrusted input may lead to command injection. |
| i LOW | `bandit` | `scanner/deps_scan.py:9` | `B404` | Fix security finding B404 in scanner/deps_scan.py:9. Issue: Potential command injection risk due to `subprocess` module import. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B607` | Fix security finding B607 in scanner/deps_scan.py:13. Issue: Process started with partial executable path, risking execution of unintended programs. |
| i LOW | `bandit` | `scanner/deps_scan.py:13` | `B603` | Fix security finding B603 in scanner/deps_scan.py:13. Issue: `subprocess` call with untrusted input may lead to command injection. |
| i LOW | `bandit` | `scanner/secrets_scan.py:10` | `B404` | Fix security finding B404 in scanner/secrets_scan.py:10. Issue: Potential command injection risk due to `subprocess` module import. |
| i LOW | `bandit` | `scanner/secrets_scan.py:25` | `B607` | Fix security finding B607 in scanner/secrets_scan.py:25. Issue: Process started with partial executable path, risking execution of unintended programs. |
| i LOW | `bandit` | `scanner/secrets_scan.py:25` | `B603` | Fix security finding B603 in scanner/secrets_scan.py:25. Issue: `subprocess` call with untrusted input may lead to command injection. |
| i LOW | `bandit` | `test_samples/vulnerable_app.py:5` | `B404` | Fix security finding B404 in test_samples/vulnerable_app.py:5. Issue: Potential command injection risk due to `subprocess` module import. |
| i LOW | `bandit` | `test_samples/vulnerable_app.py:15` | `B105` | Fix security finding B105 in test_samples/vulnerable_app.py:15. Issue: Hardcoded password detected, posing a significant security risk. |


**AI:** Gemini enrichment completed.
