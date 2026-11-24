// Demo Express app with intentionally vulnerable dependencies
// Some packages are USED (reachable), others are INSTALLED BUT NEVER IMPORTED (unreachable)

const express = require('express');
const _ = require('lodash');
const axios = require('axios');
const jwt = require('jsonwebtoken');
// NOTE: minimist, qs, tar, semver, node-fetch, yaml are installed but NOT imported here

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'demo-secret';

// --- REACHABLE: lodash _.template (CVE-2021-23337 — template injection) ---
app.post('/api/render', (req, res) => {
  try {
    const template = _.template(req.body.template);
    const result = template(req.body.data || {});
    res.json({ rendered: result });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --- REACHABLE: axios SSRF via URL (CVE-2021-3749) ---
app.get('/api/fetch', async (req, res) => {
  try {
    const response = await axios.get(req.query.url);
    res.json({ data: response.data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- REACHABLE: jsonwebtoken (various CVEs in 8.x) ---
app.post('/api/login', (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'username required' });
  const token = jwt.sign({ sub: username, role: 'user' }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

app.get('/api/profile', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'no token' });
  try {
    const decoded = jwt.verify(auth.replace('Bearer ', ''), JWT_SECRET);
    res.json({ user: decoded });
  } catch (err) {
    res.status(401).json({ error: 'invalid token' });
  }
});

// --- REACHABLE: express itself (older 4.17.1 has CVEs) ---
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

// --- NOT REACHABLE: minimist, qs, tar, semver, node-fetch, yaml ---
// These are in package.json but never imported or used in the codebase.
// Sealer should detect them as vulnerabilities but mark them as NOT reachable.

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Demo app running on port ${PORT}`);
});
