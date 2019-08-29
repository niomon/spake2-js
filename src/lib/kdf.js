const hkdf = require('futoin-hkdf')

/**
 * A key derivation function (KDF) based on HMAC with SHA256.
 *
 * @param {Buffer} salt The salt for the HKDF.
 * @param {Buffer} ikm The input key material.
 * @param {Buffer} info The info for the KDF.
 * @returns {Buffer} The derived key.
 */
function hkdfSha256 (salt, ikm, info) {
  return hkdf(ikm, 32, { salt, info, hash: 'SHA-256' })
}

exports.hkdfSha256 = hkdfSha256
