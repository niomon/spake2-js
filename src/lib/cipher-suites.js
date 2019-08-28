const elliptic = require('./elliptic')
const scrypt = require('./scrypt')
const hash = require('./hash')
const hmac = require('./hmac')

/**
 * @typedef {object} Curve
 * @property {*} group Group.
 * @property {*} P P.
 * @property {*} p Order.
 * @property {*} h Cofactor.
 * @property {*} M M.
 * @property {*} N N.
 */

/**
 * @typedef {object} CipherSuite
 * @property {Curve} curve Curve.
 * @property {Function} hash Hash.
 * @property {Function} kdf Kdf.
 * @property {Function} mac Mac.
 * @property {Function} mhf Mhf.
 */
const suiteEd25519Sha256HkdfHmacScrypt = {
  curve: elliptic.Elliptic(elliptic.CURVES.ed25519),
  hash: hash.sha256,
  kdf: 1,
  mac: hmac.hmacSha256,
  mhf: scrypt.scrypt
}

/**
 * @enum {CipherSuite}
 */
const cipherSuites = {
  'ED25519-SHA256-HKDF-HMAC-SCRYPT': suiteEd25519Sha256HkdfHmacScrypt
}

module.export = cipherSuites
