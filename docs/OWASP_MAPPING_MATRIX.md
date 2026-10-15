# OWASP Top 10 (2021) Multi-Language Mapping Matrix

This document provides a comprehensive mapping of the **OWASP Top 10 Web Application Security Risks (2021)** to their Common Weakness Enumerations (CWEs), benchmark implementations, detection rules, and regression test verifications across the top 6 enterprise web programming languages.

---

## Matrix Overview

| OWASP Category | CWE ID & Title | Supported Languages | Benchmark Sample | Semgrep Rule ID | Patched Strategy | Regression Verification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **A01: Broken Access Control** | **CWE-285** / **CWE-639** (IDOR, Missing Auth) | Python, JS/TS, Go, PHP | `app_vulnerable.py`, `app_vulnerable.js`, `vulnerable.go` | `owasp-a01-missing-auth-decorator-python`, `owasp-a01-direct-object-reference-js` | Bearer token / RBAC decorator, tenancy/ownership check | Reject unauthenticated & unowned requests; preserve valid profile fetching |
| **A02: Cryptographic Failures** | **CWE-798** (Hardcoded Keys), **CWE-328** (Weak Hash) | Python, Java, PHP, C# | `app_vulnerable.py`, `VulnerableEndpoints.java`, `vulnerable.php`, `VulnerableEndpoints.cs` | `owasp-a02-hardcoded-secret-key-python`, `owasp-a02-weak-hash-algorithm-java` | Environment variable configuration; SHA-256 / bcrypt / PBKDF2 hashing | Valid cryptographic output preserved; no raw keys in version control |
| **A03: Injection** | **CWE-89** (SQLi), **CWE-78** (Command Injection) | Python, JS/TS, Java, Go, PHP, C# | `app_vulnerable.py`, `app_vulnerable.js`, `VulnerableEndpoints.java`, `vulnerable.go`, `vulnerable.php`, `VulnerableEndpoints.cs` | `owasp-a03-sql-injection-python`, `owasp-a03-command-injection-nodejs`, `owasp-a03-sql-injection-golang`, `owasp-a03-sql-injection-php`, `owasp-a03-sql-injection-csharp` | Parameterized queries (`?`, `:param`, `@param`), `execFile` with argument array | Injection payload returns 0 rows (treated as literal); normal query returns exact data |
| **A04: Insecure Design** | **CWE-307** (Improper Rate Limiting) | JS/TS, Python | `app_vulnerable.js` | `owasp-a04-unrestricted-rate-limit-js` | In-memory / Redis rate limiting middleware on auth routes | Throttling limits abusive attempts; legitimate requests allowed within threshold |
| **A05: Security Misconfiguration** | **CWE-489** (Active Debug Code), **CWE-942** (CORS Permissive) | Python, JS/TS | `app_vulnerable.py`, `app_vulnerable.js` | `owasp-a05-cors-wildcard-credentials-js`, `owasp-a05-debug-mode-enabled-python` | `debug=False`, explicit origin allowlisting for CORS | Diagnostic errors hidden; cross-origin requests restricted to valid domain |
| **A06: Vulnerable & Outdated Components** | **CWE-1104** (Outdated Libraries) | Multi-Language | `package.json`, `pom.xml`, `requirements.txt`, `composer.json`, `Benchmark.csproj` | GitHub Actions / `npm audit` / `bandit` / `trivy` | Version pinning, automated dependency update alerts | Dependencies resolve cleanly without known CVEs |
| **A07: Identification & Auth Failures** | **CWE-287** (Improper Authentication) | Python, JS/TS, PHP | `app_vulnerable.js`, `vulnerable.php` | `owasp-a07-plaintext-password-compare-python` | Constant-time password hashing (`crypto.timingSafeEqual`, `password_verify`) | Valid credentials succeed; incorrect credentials rejected; timing attacks prevented |
| **A08: Software & Data Integrity Failures** | **CWE-502** (Deserialization of Untrusted Data) | Python, Java, PHP | `app_vulnerable.py`, `VulnerableEndpoints.java`, `vulnerable.php` | `owasp-a08-unsafe-pickle-python` | Safe structured serialization (JSON / schema validation) | Valid session data successfully read; arbitrary object instantiation blocked |
| **A09: Security Logging & Monitoring Failures** | **CWE-778** (Insufficient Logging) | Multi-Language | Framework-wide | Semgrep rule patterns | Structured audit logging for administrative actions and failed logins | Log events emitted with timestamps and anonymized identifiers |
| **A10: Server-Side Request Forgery (SSRF)** | **CWE-918** (SSRF) | Python, JS/TS, Java, Go | `app_vulnerable.py`, `VulnerableEndpoints.java`, `vulnerable.go` | `owasp-a10-ssrf-unvalidated-url-python`, `owasp-a10-ssrf-unvalidated-url-node` | Hostname allowlist, IP validation blocking private/loopback/metadata addresses | Requests to `127.0.0.1` and `169.254.169.254` blocked; allowed public targets fetch safely |

---

## Language-Specific Implementation Paths

### 1. Python (`benchmarks/python/`)
- **Vulnerable:** `app_vulnerable.py` (Flask)
- **Patched:** `app_patched.py` (Secure Flask)
- **Test Suite:** `test_regression.py` (Pytest & Unittest)
- **Run Tests:** `python test_regression.py`

### 2. JavaScript / TypeScript (`benchmarks/javascript/`)
- **Vulnerable:** `app_vulnerable.js` (Express.js)
- **Patched:** `app_patched.js` (Secure Express)
- **Test Suite:** `test_regression.test.js` (Native Node Test Runner)
- **Run Tests:** `node --test test_regression.test.js`

### 3. Java (`benchmarks/java/`)
- **Vulnerable:** `src/main/java/com/patchproof/benchmark/VulnerableEndpoints.java`
- **Patched:** `src/main/java/com/patchproof/benchmark/PatchedEndpoints.java`
- **Test Suite:** `src/test/java/com/patchproof/benchmark/RegressionTest.java` (JUnit 5)
- **Run Tests:** `mvn test`

### 4. Go (`benchmarks/golang/`)
- **Vulnerable:** `vulnerable.go` (net/http)
- **Patched:** `patched.go` (Secure net/http)
- **Test Suite:** `regression_test.go` (Go Testing)
- **Run Tests:** `go test -v ./...`

### 5. PHP (`benchmarks/php/`)
- **Vulnerable:** `vulnerable.php`
- **Patched:** `patched.php`
- **Test Suite:** `RegressionTest.php` (PHPUnit)
- **Run Tests:** `vendor/bin/phpunit RegressionTest.php`

### 6. C# / .NET (`benchmarks/csharp/`)
- **Vulnerable:** `VulnerableEndpoints.cs`
- **Patched:** `PatchedEndpoints.cs`
- **Test Suite:** `RegressionTests.cs` (xUnit)
- **Run Tests:** `dotnet test`
