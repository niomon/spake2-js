const crypto = require('crypto')

/**
 * Computes a hashed content with the Secure Hash Algorithm 2 (SHA2 / SHA256) algorithm.
 *
 * @param {Buffer} content The content to be hashed.
 * @returns {Buffer} The hashed content.
 */
function sha256 (content) {
  return crypto.createHash('sha256').update(content).digest()
}

exports.sha256 = sha256
