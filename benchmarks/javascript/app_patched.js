/**
 * PatchProof AI Benchmark - JavaScript / Node.js (Patched Implementation)
 * Demonstrates secure fixes with verified regression safety.
 */
const express = require('express');
const cors = require('cors');
const { execFile } = require('child_process');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// PATCH A05: Explicit, safe CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || 'https://mywebsite.com',
  credentials: true
}));

const userDatabase = {
  1: { id: 1, name: 'Alice Smith', email: 'alice@example.com', ssn: '999-01-1234' },
  2: { id: 2, name: 'Bob Jones', email: 'bob@example.com', ssn: '999-02-5678' }
};

// Helper middleware for authentication
const authenticateUser = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader === 'Bearer user-1-token') {
    req.user = { id: 1, role: 'user' };
    return next();
  } else if (authHeader === 'Bearer admin-token') {
    req.user = { id: 0, role: 'admin' };
    return next();
  }
  return res.status(401).json({ error: 'Authentication required' });
};

// PATCH A01: Object-level access control check & SSN field redaction
app.get('/api/users/:id', authenticateUser, (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  // Prevent unauthorized access to other users' sensitive records
  if (req.user.role !== 'admin' && req.user.id !== targetId) {
    return res.status(403).json({ error: 'Access denied: Cannot access other profiles' });
  }

  const user = userDatabase[targetId];
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  // Sanitize sensitive fields unless admin
  const sanitized = {
    id: user.id,
    name: user.name,
    email: user.email,
    ...(req.user.role === 'admin' ? { ssn: user.ssn } : {})
  };

  return res.json({ status: 'success', data: sanitized });
});

// PATCH A03: Safe command execution with execFile and strict host validation
const HOST_REGEX = /^[a-zA-Z0-9.-]+$/;

app.post('/api/tools/ping', (req, res) => {
  const host = req.body.host || '';
  if (!HOST_REGEX.test(host)) {
    return res.status(400).json({ error: 'Invalid hostname format' });
  }

  // SECURE: execFile prevents shell command chaining (; & | ` etc.)
  const pingCmd = process.platform === 'win32' ? 'ping.exe' : 'ping';
  const pingArgs = process.platform === 'win32' ? ['-n', '1', host] : ['-c', '1', host];

  execFile(pingCmd, pingArgs, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: 'Host lookup failed' });
    }
    return res.json({ status: 'success', output: stdout });
  });
});

// PATCH A07: Constant-time hash verification
const ADMIN_HASH = crypto.createHash('sha256').update('admin123').digest('hex');

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  const inputHash = crypto.createHash('sha256').update(password).digest('hex');
  const userMatches = username === 'admin';
  const passMatches = crypto.timingSafeEqual(Buffer.from(inputHash), Buffer.from(ADMIN_HASH));

  if (userMatches && passMatches) {
    return res.json({ status: 'success', token: 'verified-secure-session-token' });
  }
  return res.status(401).json({ error: 'Invalid credentials' });
});

module.exports = app;

if (require.main === module) {
  app.listen(3000, () => console.log('Patched server listening on port 3000'));
}
