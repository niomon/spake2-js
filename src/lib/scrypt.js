const scryptLib = require('scrypt-js')

/**
 * Use [scrypt](https://en.wikipedia.org/wiki/Scrypt) to hash the passphrase along with a given
 * salt and control parameters.
 *
 * @private
 * @param {Buffer} passphrase The characters to be hashed.
 * @param {Buffer} salt The salt that protects against rainbow table attacks.
 * @param {number} n The cost parameter for scrypt.
 * @param {number} r The block size parameter for scrypt.
 * @param {number} p The parallelization parameter for scrypt.
 * @example
 * await scrypt(Buffer.from('password'), Buffer.from('NaCl'), 1024, 8, 16)
 * // returns <Buffer fd ba be 1c 9d 34 72 00 78 56 ...>
 * @returns {Promise<Buffer>} The hash value.
 */
function scrypt (passphrase, salt, n, r, p) {
  return new Promise(function (resolve, reject) {
    scryptLib(passphrase, salt, n, r, p, 64, function (error, _, key) {
      if (error) return reject(error)
      else if (key) resolve(Buffer.from(key))
    })
  })
}

exports.scrypt = scrypt
