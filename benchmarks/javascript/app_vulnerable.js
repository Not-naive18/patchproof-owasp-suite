/**
 * PatchProof AI Benchmark - JavaScript / Node.js (Vulnerable Implementation)
 * Demonstrates OWASP Top 10 vulnerabilities in Express.js.
 */
const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');

const app = express();
app.use(express.json());

// OWASP A05:2021 - Security Misconfiguration (Permissive CORS with credentials)
app.use(cors({ origin: '*', credentials: true }));

const userDatabase = {
  1: { id: 1, name: 'Alice Smith', email: 'alice@example.com', ssn: '999-01-1234' },
  2: { id: 2, name: 'Bob Jones', email: 'bob@example.com', ssn: '999-02-5678' }
};

// OWASP A01:2021 - Broken Access Control / IDOR
// Any user can fetch any other user's private SSN without authorization check
app.get('/api/users/:id', (req, res) => {
  const userId = req.params.id;
  const user = userDatabase[userId];
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  // VULNERABLE: Direct access to record without role or ownership validation
  return res.json({ status: 'success', data: user });
});

// OWASP A03:2021 - Injection (Command Injection)
// Using child_process.exec with unsanitized user-provided domain or filename
app.post('/api/tools/ping', (req, res) => {
  const host = req.body.host || '';
  // VULNERABLE: Direct string interpolation into shell command
  exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: stderr || error.message });
    }
    return res.json({ status: 'success', output: stdout });
  });
});

// OWASP A07:2021 - Identification and Authentication Failures
// Comparing plain text passwords directly without salt or slow hash
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === 'admin123') { // VULNERABLE
    return res.json({ status: 'success', token: 'hardcoded-session-token' });
  }
  return res.status(401).json({ error: 'Invalid credentials' });
});

module.exports = app;

if (require.main === module) {
  app.listen(3000, () => console.log('Vulnerable server listening on port 3000'));
}
