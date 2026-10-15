# PatchProof AI Integration Architecture

This guide describes how **PatchProof AI** utilizes this repository to execute its complete **Detect. Prove. Patch. Verify.** pipeline.

---

```
  ┌─────────────────────────────────────────────────────────┐
  │                   1. INGESTION                          │
  │     Developer submits GitHub Repo URL to Portal         │
  └──────────────────────────┬──────────────────────────────┘
                             ▼
  ┌─────────────────────────────────────────────────────────┐
  │                   2. DETECTION                          │
  │   Semgrep + Multi-Language Scanner (`run_scanner.py`)   │
  │   Flags OWASP Top 10 vulnerabilities (SARIF/JSON)       │
  └──────────────────────────┬──────────────────────────────┘
                             ▼
  ┌─────────────────────────────────────────────────────────┐
  │                3. ML CLASSIFICATION                     │
  │   Trained OWASP Java Classifier (TF-IDF + Scikit-Learn) │
  │   Cross-validates CWEs with 80.57% macro F1 accuracy    │
  └──────────────────────────┬──────────────────────────────┘
                             ▼
  ┌─────────────────────────────────────────────────────────┐
  │                 4. AI PATCHING (Groq)                   │
  │   LLM analyzes root cause and produces minimal unified   │
  │   diff without rewriting unrelated code                │
  └──────────────────────────┬──────────────────────────────┘
                             ▼
  ┌─────────────────────────────────────────────────────────┐
  │               5. REGRESSION VERIFICATION                │
  │   Isolated working copy reruns test suites:             │
  │   - Security Test: Verifies exploit is neutralized      │
  │   - Unit Test: Verifies existing features work          │
  └──────────────────────────┬──────────────────────────────┘
                             ▼
  ┌─────────────────────────────────────────────────────────┐
  │                6. EVIDENCE & REVIEW                     │
  │   Security Reviewer Portal displays diffs, logs, and    │
  │   verification proof for final human approval           │
  └─────────────────────────────────────────────────────────┘
```

---

## Pipeline Stage Breakdown

### Stage 1: Repository Ingestion
The **Developer Portal** clones the target repository and detects the language ecosystem:
- Python (`requirements.txt`, `pyproject.toml`)
- JavaScript/TypeScript (`package.json`)
- Java (`pom.xml`, `build.gradle`)
- Go (`go.mod`)
- PHP (`composer.json`)
- C# (`*.csproj`, `*.sln`)

### Stage 2: Security Detection
The ingestion pipeline runs the scanner against the codebase:
```bash
python scanner/run_scanner.py --path . --format sarif --output scan-results.sarif
```
The output identifies the exact file, line number, vulnerable code snippet, and CWE identifier.

### Stage 3: ML Classification Layer
For supported Java code blocks, code chunks are passed to the custom-trained **OWASP Benchmark Java v1.2 ML Classifier**:
- Trained on 1,501 training samples and 375 held-out evaluation samples.
- Classifies into 7 CWE categories with 80.57% macro F1 score.
- Acts as an independent second-opinion classifier to confirm static analysis findings.

### Stage 4: AI Root-Cause Analysis and Patch Generation
The vulnerable code snippet, context, and CWE metadata are sent to the Groq-hosted LLM with the following system prompt:
> *"Produce a minimal patch in unified diff format that neutralizes the identified CWE vulnerability. Do not alter existing function signatures, return value types, or business logic."*

### Stage 5: Regression Verification (The Core Innovation)
1. The patch is applied in an isolated workspace copy.
2. The language regression test suite is executed:
   - Python: `python -m unittest test_regression.py`
   - Node.js: `node --test test_regression.test.js`
   - Java: `mvn test`
   - Go: `go test -v ./...`
   - PHP: `vendor/bin/phpunit RegressionTest.php`
   - C#: `dotnet test`
3. **Pass Criteria:**
   - Security verification passes (exploit payload neutralized).
   - Functional test suite passes (0 regressions in existing business logic).
   - If functional tests break, the error output is fed back into the patch generator for automated retry.

### Stage 6: Security Reviewer Portal
The reviewer is presented with:
- **Patch Studio:** Side-by-side diff between `app_vulnerable` and `app_patched`.
- **Test Evidence:** Real-time stdout/stderr from test suite execution showing 100% test pass.
- **Approval Button:** One-click PR creation or merge back into the main branch.
