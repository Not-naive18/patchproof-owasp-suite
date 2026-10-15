/**
 * PatchProof AI Regression Test Suite - JavaScript / Node.js
 * Verifies security remediation and business logic preservation using native node:test.
 */
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const appPatched = require('./app_patched');

function makeRequest(app, method, path, headers = {}, body = null) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.listen(0, () => {
      const port = server.address().port;
      const options = {
        hostname: '127.0.0.1',
        port: port,
        path: path,
        method: method,
        headers: headers
      };

      const req = http.request(options, (res) => {
        let rawData = '';
        res.on('data', chunk => rawData += chunk);
        res.on('end', () => {
          server.close();
          let parsed;
          try { parsed = JSON.parse(rawData); } catch (e) { parsed = rawData; }
          resolve({ status: res.statusCode, headers: res.headers, body: parsed });
        });
      });

      req.on('error', (err) => {
        server.close();
        reject(err);
      });

      if (body) {
        req.setHeader('Content-Type', 'application/json');
        req.write(JSON.stringify(body));
      }
      req.end();
    });
  });
}

test('Preserves Login Business Functionality with Correct Credentials', async () => {
  const res = await makeRequest(appPatched, 'POST', '/api/login', {}, {
    username: 'admin',
    password: 'admin123'
  });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.status, 'success');
  assert.strictEqual(res.body.token, 'verified-secure-session-token');
});

test('Rejects Invalid Login Credentials', async () => {
  const res = await makeRequest(appPatched, 'POST', '/api/login', {}, {
    username: 'admin',
    password: 'wrongpassword'
  });
  assert.strictEqual(res.status, 401);
});

test('Remediates IDOR: User 1 cannot inspect User 2 profile', async () => {
  const res = await makeRequest(appPatched, 'GET', '/api/users/2', {
    authorization: 'Bearer user-1-token'
  });
  assert.strictEqual(res.status, 403);
});

test('Preserves Own Profile Access for Authorized User 1', async () => {
  const res = await makeRequest(appPatched, 'GET', '/api/users/1', {
    authorization: 'Bearer user-1-token'
  });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.status, 'success');
  assert.strictEqual(res.body.data.name, 'Alice Smith');
  // Sensitive SSN must be redacted for standard user view
  assert.strictEqual(res.body.data.ssn, undefined);
});

test('Blocks Malicious Command Injection in Ping Endpoint', async () => {
  const maliciousInput = '127.0.0.1; whoami';
  const res = await makeRequest(appPatched, 'POST', '/api/tools/ping', {}, {
    host: maliciousInput
  });
  assert.strictEqual(res.status, 400);
  assert.strictEqual(res.body.error, 'Invalid hostname format');
});
