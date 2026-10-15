# 🛡️ PatchProof AI — OWASP Top 10 Multi-Language Benchmark & Testing Suite

> **"Detect. Prove. Patch. Verify."**  
> *Developed by The OG Strivers*

[![CI Security Scan](https://img.shields.io/badge/Security%20Scan-Semgrep%20OWASP-blue.svg)](#)
[![Regression Verification](https://img.shields.io/badge/Regression%20Verification-Passing-brightgreen.svg)](#)
[![Languages](https://img.shields.io/badge/Languages-Python%20%7C%20JS%2FTS%20%7C%20Java%20%7C%20Go%20%7C%20PHP%20%7C%20C%23-orange.svg)](#)
[![OWASP Top 10](https://img.shields.io/badge/OWASP%20Top%2010-2021%20Compliant-red.svg)](https://owasp.org/Top10/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📌 Executive Summary

**What if an AI fixes a security vulnerability but accidentally breaks an existing feature of your website?**

Traditional scanners identify vulnerabilities, and generative AI can suggest code changes. But simply generating a patch does not guarantee that the vulnerability has been eradicated or that your web application still functions correctly.

**PatchProof AI** solves this with an **evidence-driven patch-verification pipeline**. This repository provides the unified multi-language testbed and automated vulnerability testing framework covering the **OWASP Top 10** across the primary enterprise web programming languages:

1. **Python** (Flask / FastAPI)
2. **JavaScript & TypeScript** (Node.js / Express)
3. **Java** (Spring Boot / Servlets)
4. **Go** (net/http / Gin)
5. **PHP** (Modern PHP / Laravel style)
6. **C# / .NET** (ASP.NET Core)

Each language includes:
- **Vulnerable Implementations:** Synthetic real-world patterns representing OWASP Top 10 CWE weaknesses.
- **Patched Implementations:** Secure, verified reference code neutralizing each vulnerability.
- **Regression Test Suites:** Unit and integration test suites that ensure business logic remains intact while proving vulnerability remediation.
- **Semgrep Rules & Scanner Engine:** Automated multi-language static analysis producing JSON and SARIF v2.1.0 reports.

---

## 🏗️ Repository Architecture

```
patchproof-owasp-suite/
├── .github/
│   └── workflows/
│       ├── security-scan.yml         # GitHub Actions: Automated Semgrep & SAST pipeline
│       └── regression-verify.yml     # GitHub Actions: Multi-language regression verification
├── .semgrep/
│   └── owasp-top10-rules.yml         # Semgrep rule definitions mapped to OWASP Top 10
├── benchmarks/
│   ├── python/                       # Flask vulnerable & patched endpoints + test_regression.py
│   ├── javascript/                   # Express vulnerable & patched endpoints + test_regression.test.js
│   ├── java/                         # Java servlets/SQLite vulnerable & patched + RegressionTest.java
│   ├── golang/                       # Go HTTP handlers vulnerable & patched + regression_test.go
│   ├── php/                          # PHP PDO vulnerable & patched + RegressionTest.php
│   └── csharp/                       # ASP.NET/Sqlite vulnerable & patched + RegressionTests.cs
├── scanner/
│   ├── run_scanner.py                # Multi-language CLI scanner (Semgrep & AST fallback)
│   ├── report_generator.py           # Formats findings into Markdown and SARIF reports
│   └── config.json                   # CWE and OWASP mappings configuration
├── docs/
│   ├── OWASP_MAPPING_MATRIX.md       # Full CWE-to-language matrix
│   └── PATCHPROOF_INTEGRATION.md     # Ingestion & Developer/Reviewer Portal integration guide
├── .gitignore
├── LICENSE
└── README.md
```

---

## 🎯 OWASP Top 10 Coverage

| OWASP Category | CWE ID | Vulnerability Type | Language Support |
| :--- | :--- | :--- | :--- |
| **A01:2021** | CWE-285 / CWE-639 | Broken Access Control / IDOR | Python, JS/TS, Go, PHP |
| **A02:2021** | CWE-798 / CWE-328 | Cryptographic Failures (Keys, MD5) | Python, Java, PHP, C# |
| **A03:2021** | CWE-89 / CWE-78 | Injection (SQLi, OS Command) | All 6 Languages |
| **A04:2021** | CWE-307 | Insecure Design (Missing Rate Limits) | JS/TS, Python |
| **A05:2021** | CWE-489 / CWE-942 | Security Misconfiguration (Debug, CORS) | Python, JS/TS |
| **A06:2021** | CWE-1104 | Vulnerable & Outdated Components | All 6 Package Managers |
| **A07:2021** | CWE-287 | Identification & Authentication Failures | Python, JS/TS, PHP |
| **A08:2021** | CWE-502 | Software & Data Integrity (Deserialization) | Python, Java, PHP |
| **A09:2021** | CWE-778 | Security Logging & Monitoring Failures | All 6 Frameworks |
| **A10:2021** | CWE-918 | Server-Side Request Forgery (SSRF) | Python, JS, Java, Go |

*For complete mapping details, see [docs/OWASP_MAPPING_MATRIX.md](docs/OWASP_MAPPING_MATRIX.md).*

---

## 🚀 Quick Start Guide

### 1. Run the Multi-Language Vulnerability Scanner

The scanner can be executed against any local codebase or website repository:

```bash
# Run multi-language scan with console output
python scanner/run_scanner.py --path benchmarks/

# Generate GitHub-compliant SARIF report
python scanner/run_scanner.py --path benchmarks/ --format sarif --output scan-results.sarif

# Generate JSON report for PatchProof AI ingestion
python scanner/run_scanner.py --path benchmarks/ --format json --output scan-results.json

# Generate Markdown Audit Summary
python scanner/report_generator.py
```

### 2. Run Language Regression Test Suites

To verify that the patches neutralize the vulnerabilities without breaking functionality:

#### 🐍 Python
```bash
cd benchmarks/python
python test_regression.py
# Or using pytest:
pytest test_regression.py -v
```

#### 🟨 JavaScript / Node.js
```bash
cd benchmarks/javascript
node --test test_regression.test.js
```

#### ☕ Java
```bash
cd benchmarks/java
mvn test
```

#### 🐹 Go
```bash
cd benchmarks/golang
go test -v ./...
```

#### 🐘 PHP
```bash
cd benchmarks/php
php vendor/bin/phpunit RegressionTest.php
```

#### 🔷 C# / .NET
```bash
cd benchmarks/csharp
dotnet test
```

---

## 🔄 The PatchProof AI Pipeline

This repository is designed to integrate directly with **PatchProof AI's 6-Stage Pipeline**:

```
[Ingestion] ➔ [Detection] ➔ [ML Classifier] ➔ [AI Patching] ➔ [Verification] ➔ [Reviewer Portal]
```

1. **Repository Ingestion:** Developers submit GitHub repository URLs through the **Developer Portal**.
2. **Security Detection:** Static analysis rules (`.semgrep/owasp-top10-rules.yml` & `scanner/run_scanner.py`) identify weaknesses.
3. **ML Classification:** Custom-trained **OWASP Benchmark Java v1.2** classifier provides independent category validation (80.57% macro F1 score).
4. **AI Patch Generation:** Groq-hosted LLM derives minimal unified diffs.
5. **Regression Verification:** Test suites execute in an isolated environment to verify that security issues are remediated without breaking existing features.
6. **Security Reviewer Portal:** Visual inspection of side-by-side diffs, test logs, and reproducible evidence before merge.

*Detailed architectural notes are available in [docs/PATCHPROOF_INTEGRATION.md](docs/PATCHPROOF_INTEGRATION.md).*

---

## 🤝 Contributing

Contributions to add further CWE categories, framework integrations (Django, NestJS, Spring WebFlux, Laravel, Gin), or scanner rules are welcome!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/cwe-expansion`)
3. Add vulnerable implementation, patched code, and regression tests
4. Commit your changes (`git commit -m 'feat: add CWE-xxx benchmark'`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
