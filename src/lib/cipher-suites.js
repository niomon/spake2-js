const EC = require('elliptic').ec
const scrypt = require('scrypt-js')
const crypto = require('crypto')

/**
 * @typedef {object} Curve
 * @property {*} group Group.
 * @property {*} P P.
 * @property {*} p Order.
 * @property {*} H Cofactor.
 * @property {*} M M.
 * @property {*} N N.
 */

/**
 * @typedef {object} CipherSuite
 * @property {Curve} curve Curve.
 * @property {Hash} hash Hash.
 * @property {KDF} kdf Kdf.
 * @property {MAC} mac Mac.
 * @property {MHF} mhf Mhf.
 */
const suiteEd25519Sha256HkdfHmacScrypt = {
  curve: new EC('curve25519'),
  hash: crypto.createHash('sha256'),
  kdf: 1,
  mac: crypto.createHmac('sha256', 'a secret'), // TODO
  mhf: scrypt
}

/**
 * @enum {CipherSuite}
 */
const cipherSuites = {
  'ED25519-SHA256-HKDF-HMAC-SCRYPT': suiteEd25519Sha256HkdfHmacScrypt
}

module.export = cipherSuites
