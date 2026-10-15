# 🛡️ PatchProof AI Security Audit Report
**Total Findings Detected:** 25

| # | Severity | OWASP Category | CWE | File Location | Line |
|---|---|---|---|---|---|
| 1 | 🟠 HIGH | A02:2021 - Cryptographic Failures | CWE-328 | `VulnerableEndpoints.cs` | 31 |
| 2 | 🔴 CRITICAL | A03:2021 - Injection | CWE-89 | `VulnerableEndpoints.cs` | 42 |
| 3 | 🟠 HIGH | A01:2021 - Broken Access Control | CWE-285 | `patched.go` | 19 |
| 4 | 🟠 HIGH | A01:2021 - Broken Access Control | CWE-285 | `vulnerable.go` | 16 |
| 5 | 🟠 HIGH | A10:2021 - Server-Side Request Forgery | CWE-918 | `vulnerable.go` | 47 |
| 6 | 🟠 HIGH | A10:2021 - Server-Side Request Forgery | CWE-918 | `PatchedEndpoints.java` | 89 |
| 7 | 🟠 HIGH | A02:2021 - Cryptographic Failures | CWE-328 | `VulnerableEndpoints.java` | 37 |
| 8 | 🔴 CRITICAL | A03:2021 - Injection | CWE-89 | `VulnerableEndpoints.java` | 51 |
| 9 | 🔴 CRITICAL | A08:2021 - Software and Data Integrity Failures | CWE-502 | `VulnerableEndpoints.java` | 63 |
| 10 | 🟠 HIGH | A10:2021 - Server-Side Request Forgery | CWE-918 | `VulnerableEndpoints.java` | 72 |
| 11 | 🟠 HIGH | A01:2021 - Broken Access Control | CWE-285 | `app_patched.js` | 38 |
| 12 | 🟠 HIGH | A05:2021 - Security Misconfiguration | CWE-942 | `app_vulnerable.js` | 13 |
| 13 | 🟠 HIGH | A01:2021 - Broken Access Control | CWE-285 | `app_vulnerable.js` | 22 |
| 14 | 🔴 CRITICAL | A03:2021 - Injection | CWE-78 | `app_vulnerable.js` | 37 |
| 15 | 🟠 HIGH | A02:2021 - Cryptographic Failures | CWE-328 | `vulnerable.php` | 13 |
| 16 | 🟠 HIGH | A02:2021 - Cryptographic Failures | CWE-328 | `vulnerable.php` | 28 |
| 17 | 🔴 CRITICAL | A08:2021 - Software and Data Integrity Failures | CWE-502 | `vulnerable.php` | 34 |
| 18 | 🟠 HIGH | A01:2021 - Broken Access Control | CWE-285 | `app_patched.py` | 38 |
| 19 | 🟠 HIGH | A10:2021 - Server-Side Request Forgery | CWE-918 | `app_patched.py` | 98 |
| 20 | 🔴 CRITICAL | A02:2021 - Cryptographic Failures | CWE-798 | `app_vulnerable.py` | 14 |
| 21 | 🟠 HIGH | A01:2021 - Broken Access Control | CWE-285 | `app_vulnerable.py` | 32 |
| 22 | 🔴 CRITICAL | A03:2021 - Injection | CWE-89 | `app_vulnerable.py` | 48 |
| 23 | 🔴 CRITICAL | A08:2021 - Software and Data Integrity Failures | CWE-502 | `app_vulnerable.py` | 61 |
| 24 | 🟠 HIGH | A10:2021 - Server-Side Request Forgery | CWE-918 | `app_vulnerable.py` | 74 |
| 25 | 🟡 MEDIUM | A05:2021 - Security Misconfiguration | CWE-489 | `app_vulnerable.py` | 79 |

## Detailed Remediation Guidance

### Finding 1: A02:2021 - Cryptographic Failures (CWE-328)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/csharp/VulnerableEndpoints.cs` (Line 31)
- **Vulnerable Snippet:**
```
using var md5 = MD5.Create();
```
- **Advisory:** Insecure cryptographic hash algorithm (MD5) used. Use SHA-256 or bcrypt.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 2: A03:2021 - Injection (CWE-89)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/csharp/VulnerableEndpoints.cs` (Line 42)
- **Vulnerable Snippet:**
```
cmd.CommandText = "SELECT Email, CreditLimit FROM Customers WHERE Email = '" + emailFilter + "'";
```
- **Advisory:** SQL Injection: Dynamic string concatenation or unparameterized variable interpolation in query.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 3: A01:2021 - Broken Access Control (CWE-285)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/golang/patched.go` (Line 19)
- **Vulnerable Snippet:**
```
func (s *PatchedServer) AdminStatsHandler(w http.ResponseWriter, r *http.Request) {
```
- **Advisory:** Potential Broken Access Control / IDOR: Sensitive endpoint or object accessed without tenant or role checks.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 4: A01:2021 - Broken Access Control (CWE-285)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/golang/vulnerable.go` (Line 16)
- **Vulnerable Snippet:**
```
func (s *VulnerableServer) AdminStatsHandler(w http.ResponseWriter, r *http.Request) {
```
- **Advisory:** Potential Broken Access Control / IDOR: Sensitive endpoint or object accessed without tenant or role checks.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 5: A10:2021 - Server-Side Request Forgery (CWE-918)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/golang/vulnerable.go` (Line 47)
- **Vulnerable Snippet:**
```
resp, err := http.Get(target)
```
- **Advisory:** SSRF: Remote network request made to user-controlled destination without host validation.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 6: A10:2021 - Server-Side Request Forgery (CWE-918)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/java/src/main/java/com/patchproof/benchmark/PatchedEndpoints.java` (Line 89)
- **Vulnerable Snippet:**
```
HttpURLConnection connection = (HttpURLConnection) url.openConnection();
```
- **Advisory:** SSRF: Remote network request made to user-controlled destination without host validation.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 7: A02:2021 - Cryptographic Failures (CWE-328)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/java/src/main/java/com/patchproof/benchmark/VulnerableEndpoints.java` (Line 37)
- **Vulnerable Snippet:**
```
MessageDigest md = MessageDigest.getInstance("MD5");
```
- **Advisory:** Insecure cryptographic hash algorithm (MD5) used. Use SHA-256 or bcrypt.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 8: A03:2021 - Injection (CWE-89)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/java/src/main/java/com/patchproof/benchmark/VulnerableEndpoints.java` (Line 51)
- **Vulnerable Snippet:**
```
String query = "SELECT username, balance FROM accounts WHERE username = '" + userInput + "'";
```
- **Advisory:** SQL Injection: Dynamic string concatenation or unparameterized variable interpolation in query.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 9: A08:2021 - Software and Data Integrity Failures (CWE-502)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/java/src/main/java/com/patchproof/benchmark/VulnerableEndpoints.java` (Line 63)
- **Vulnerable Snippet:**
```
ObjectInputStream ois = new ObjectInputStream(bais)) {
```
- **Advisory:** Unsafe Deserialization: Parsing untrusted binary stream may allow arbitrary code execution.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 10: A10:2021 - Server-Side Request Forgery (CWE-918)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/java/src/main/java/com/patchproof/benchmark/VulnerableEndpoints.java` (Line 72)
- **Vulnerable Snippet:**
```
HttpURLConnection connection = (HttpURLConnection) url.openConnection();
```
- **Advisory:** SSRF: Remote network request made to user-controlled destination without host validation.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 11: A01:2021 - Broken Access Control (CWE-285)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/javascript/app_patched.js` (Line 38)
- **Vulnerable Snippet:**
```
app.get('/api/users/:id', authenticateUser, (req, res) => {
```
- **Advisory:** Potential Broken Access Control / IDOR: Sensitive endpoint or object accessed without tenant or role checks.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 12: A05:2021 - Security Misconfiguration (CWE-942)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/javascript/app_vulnerable.js` (Line 13)
- **Vulnerable Snippet:**
```
app.use(cors({ origin: '*', credentials: true }));
```
- **Advisory:** Insecure CORS Policy: Wildcard origin with credentials enabled.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 13: A01:2021 - Broken Access Control (CWE-285)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/javascript/app_vulnerable.js` (Line 22)
- **Vulnerable Snippet:**
```
app.get('/api/users/:id', (req, res) => {
```
- **Advisory:** Potential Broken Access Control / IDOR: Sensitive endpoint or object accessed without tenant or role checks.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 14: A03:2021 - Injection (CWE-78)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/javascript/app_vulnerable.js` (Line 37)
- **Vulnerable Snippet:**
```
exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
```
- **Advisory:** OS Command Injection: Unsanitized user argument passed into system shell.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 15: A02:2021 - Cryptographic Failures (CWE-328)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/php/vulnerable.php` (Line 13)
- **Vulnerable Snippet:**
```
$this->pdo->exec("INSERT INTO members VALUES (1, 'alice', 'admin', '5f4dcc3b5aa765d61d8327deb882cf99')"); // md5('password')
```
- **Advisory:** Insecure cryptographic hash algorithm (MD5) used. Use SHA-256 or bcrypt.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 16: A02:2021 - Cryptographic Failures (CWE-328)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/php/vulnerable.php` (Line 28)
- **Vulnerable Snippet:**
```
return md5($inputPassword) === $storedHash;
```
- **Advisory:** Insecure cryptographic hash algorithm (MD5) used. Use SHA-256 or bcrypt.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 17: A08:2021 - Software and Data Integrity Failures (CWE-502)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/php/vulnerable.php` (Line 34)
- **Vulnerable Snippet:**
```
return unserialize($serializedData);
```
- **Advisory:** Unsafe Deserialization: Parsing untrusted binary stream may allow arbitrary code execution.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 18: A01:2021 - Broken Access Control (CWE-285)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/python/app_patched.py` (Line 38)
- **Vulnerable Snippet:**
```
@app.route("/admin/users", methods=["GET"])
```
- **Advisory:** Potential Broken Access Control / IDOR: Sensitive endpoint or object accessed without tenant or role checks.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 19: A10:2021 - Server-Side Request Forgery (CWE-918)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/python/app_patched.py` (Line 98)
- **Vulnerable Snippet:**
```
response = requests.get(target_url, timeout=3)
```
- **Advisory:** SSRF: Remote network request made to user-controlled destination without host validation.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 20: A02:2021 - Cryptographic Failures (CWE-798)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/python/app_vulnerable.py` (Line 14)
- **Vulnerable Snippet:**
```
SECRET_KEY = "SUPER_SECRET_UNENCRYPTED_KEY_12345"
```
- **Advisory:** Hardcoded secret key or sensitive credential identified in source.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 21: A01:2021 - Broken Access Control (CWE-285)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/python/app_vulnerable.py` (Line 32)
- **Vulnerable Snippet:**
```
@app.route("/admin/users", methods=["GET"])
```
- **Advisory:** Potential Broken Access Control / IDOR: Sensitive endpoint or object accessed without tenant or role checks.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 22: A03:2021 - Injection (CWE-89)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/python/app_vulnerable.py` (Line 48)
- **Vulnerable Snippet:**
```
query = f"SELECT id, name, category, price FROM products WHERE category = '{category}'"
```
- **Advisory:** SQL Injection: Dynamic string concatenation or unparameterized variable interpolation in query.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 23: A08:2021 - Software and Data Integrity Failures (CWE-502)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/python/app_vulnerable.py` (Line 61)
- **Vulnerable Snippet:**
```
payload = pickle.loads(decoded)
```
- **Advisory:** Unsafe Deserialization: Parsing untrusted binary stream may allow arbitrary code execution.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 24: A10:2021 - Server-Side Request Forgery (CWE-918)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/python/app_vulnerable.py` (Line 74)
- **Vulnerable Snippet:**
```
response = requests.get(target_url, timeout=3)
```
- **Advisory:** SSRF: Remote network request made to user-controlled destination without host validation.
- **Verification Action:** Re-run regression test suite after applying patch.

### Finding 25: A05:2021 - Security Misconfiguration (CWE-489)
- **File:** `C:/Users/Asus/.gemini/antigravity/scratch/patchproof-owasp-suite/benchmarks/python/app_vulnerable.py` (Line 79)
- **Vulnerable Snippet:**
```
app.run(host="0.0.0.0", port=5000, debug=True)
```
- **Advisory:** Security Misconfiguration: Flask application configured with debug=True in runnable code.
- **Verification Action:** Re-run regression test suite after applying patch.
