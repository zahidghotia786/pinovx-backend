// utils/signature.js
const crypto = require('crypto');
const { SECRET_KEY } = require('../config');

function generateSignature(ts, method, path, body) {
  const hmac = crypto.createHmac('sha256', SECRET_KEY);
  hmac.update(ts + method + path + body);
  return hmac.digest('hex');
}

module.exports = generateSignature;
