const crypto = require('crypto')

function sha256 (content) {
  return crypto.createHash('sha256').update(content).digest()
}

exports.sha256 = sha256
