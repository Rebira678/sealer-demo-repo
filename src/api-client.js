// API client module that uses axios
const axios = require('axios');

const API_BASE = process.env.EXTERNAL_API || 'https://api.example.com';

/**
 * Fetch data from an external API.
 * Uses axios 0.21.1 which has SSRF and ReDoS vulnerabilities.
 */
async function fetchExternalData(endpoint) {
  const response = await axios.get(`${API_BASE}${endpoint}`, {
    timeout: 5000,
    headers: {
      'User-Agent': 'sealer-demo/1.0',
    },
  });
  return response.data;
}

/**
 * Post data to an external webhook.
 */
async function postWebhook(url, payload) {
  return axios.post(url, payload, {
    timeout: 3000,
  });
}

module.exports = { fetchExternalData, postWebhook };
