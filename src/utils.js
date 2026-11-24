// Utility module that also uses lodash — proves multi-file reachability
const _ = require('lodash');

/**
 * Deep merge user config with defaults.
 * Uses lodash.merge which has prototype pollution vulnerability in older versions.
 */
function mergeConfig(defaults, userConfig) {
  return _.merge({}, defaults, userConfig);
}

/**
 * Sanitize user input by escaping HTML entities.
 * Uses lodash.escape — safe function, but the package itself is vulnerable.
 */
function sanitize(input) {
  return _.escape(input);
}

module.exports = { mergeConfig, sanitize };
