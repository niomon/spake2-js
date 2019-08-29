const crypto = require('crypto')

/**
 * Computes a key-hashed content with the Secure Hash Algorithm 2 (SHA2 / SHA256) algorithm.
 *
 * @param {Buffer} content The content to be hashed.
 * @param {Buffer} secret The secret key to compute the hash.
 * @returns {Buffer} The key-hashed content.
 */
function hmacSha256 (content, secret) {
  return crypto.createHmac('sha256', secret).update(content).digest()
}

exports.hmacSha256 = hmacSha256
