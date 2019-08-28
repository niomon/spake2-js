const crypto = require('crypto')

function hmacSha256 (content, secret) {
  return crypto.createHmac('sha256', secret).update(content).digest()
}

exports.hmacSha256 = hmacSha256
