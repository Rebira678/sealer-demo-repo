// Demo Express app with intentionally vulnerable dependencies
// Some packages are USED (reachable), others are INSTALLED BUT NEVER IMPORTED (unreachable)

const express = require('express');
const _ = require('lodash');
const axios = require('axios');
const JSON5 = require('json5');
// NOTE: minimist, qs, semver, yaml are installed but NOT imported here

const app = express();
app.use(express.json());

// --- REACHABLE: lodash _.template command injection via options.variable (CVE-2021-23337 / GHSA-35jh-r3h4-6jhm) ---
app.post('/api/render', (req, res) => {
  try {
    const template = _.template(req.body.template, { variable: req.query.v });
    const result = template(req.body.data || {});
    res.json({ rendered: result });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --- REACHABLE: axios ReDoS via URL trim (CVE-2021-3749 / GHSA-cph5-m8f7-6c5x) ---
app.get('/api/fetch', async (req, res) => {
  try {
    const response = await axios.get(req.query.url);
    res.json({ data: response.data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- REACHABLE: json5 Prototype Pollution via parse() (CVE-2022-46175 / GHSA-9c47-m6qq-7p4h) ---
app.post('/api/config', (req, res) => {
  try {
    const parsed = JSON5.parse(req.body.config);
    res.json({ parsed });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

// --- NOT REACHABLE: minimist, qs, semver, yaml ---
// These are in package.json but never imported or used in the codebase.
// Sealer marks them unreachable deterministically via the pre-check.

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Demo app running on port ${PORT}`);
  });
}

module.exports = app;
