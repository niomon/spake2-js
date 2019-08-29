const { CURVES, Elliptic, Curve } = require('./elliptic.js')
const hash = require('./hash.js')
const hmac = require('./hmac.js')
const kdf = require('./kdf.js')
const mhf = require('./mhf.js')

/**
 * @typedef {object} CipherSuite
 * @property {Curve} curve An elliptic curve.
 * @property {Function} hash A hash function.
 * @property {Function} kdf A key derivation function.
 * @property {Function} mac A message authentication code function.
 * @property {Function} mhf A memory-hard hash function.
 */
const suiteEd25519Sha256HkdfHmacScrypt = {
  curve: new Elliptic(CURVES.ed25519),
  hash: hash.sha256,
  kdf: kdf.hkdfSha256,
  mac: hmac.hmacSha256,
  mhf: mhf.scrypt
}

/**
 * Enumerate the cipher suites.
 *
 * @readonly
 * @enum {CipherSuite}
 */
const cipherSuites = {
  'ED25519-SHA256-HKDF-HMAC-SCRYPT': suiteEd25519Sha256HkdfHmacScrypt
}

exports.cipherSuites = cipherSuites
