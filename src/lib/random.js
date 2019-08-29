const BN = require('bn.js')
const crypto = require('crypto')

/**
 * Generates a random integer in `[l, r)`.
 *
 * @param {BN} l The lower bound of the random number.
 * @param {BN} r The upper bound of the random number.
 * @returns {BN} A cryptographically-random integer.
 */
function randomInteger (l, r) {
  const range = r.sub(l)
  const size = Math.ceil(range.sub(new BN(1)).toString(16).length / 2)
  const v = new BN(crypto.randomBytes(size + 8).toString('hex'), 16)
  return v.mod(range).add(l)
}

exports.randomInteger = randomInteger
