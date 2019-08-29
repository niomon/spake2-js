const scryptLib = require('scrypt-js')

/**
 * Use [scrypt](https://en.wikipedia.org/wiki/Scrypt) to hash the passphrase along with a given
 * salt and control parameters.
 *
 * @param {Buffer} passphrase The characters to be hashed.
 * @param {Buffer} salt The salt that protects against rainbow table attacks.
 * @param {object} options The options controlling the cost, block size and the parallelization.
 * @param {number} options.n The cost parameter for scrypt.
 * @param {number} options.r The block size parameter for scrypt.
 * @param {number} options.p The parallelization parameter for scrypt.
 * @example
 * await scrypt(Buffer.from('password'), Buffer.from('NaCl'), { n: 1024, r: 8, p: 16 })
 * // returns <Buffer fd ba be 1c 9d 34 72 00 78 56 ...>
 * @returns {Promise<Buffer>} The hash value.
 */
function scrypt (passphrase, salt, { n, r, p }) {
  return new Promise(function (resolve, reject) {
    scryptLib(passphrase, salt, n, r, p, 32, function (error, _, key) {
      if (error) return reject(error)
      else if (key) resolve(Buffer.from(key))
    })
  })
}

exports.scrypt = scrypt
