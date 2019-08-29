const BN = require('bn.js')
const EC = require('elliptic').ec

const TWO_POW_255 = new BN(2).pow(new BN(255))

/**
 * @typedef {object} Curve
 * @property {string} name The number of the curve.
 * @property {BN} p The order of the subgroup G with a generator P, where P is a point specified by the curve.
 * @property {BN} h The cofactor of the subgroup G.
 * @property {string} M SEC1-compressed coordinate of M.
 * @property {string} N SEC1-compressed coordinate of N.
 */
const curveEd25519 = {
  name: 'ed25519',
  // It is defined in [draft-irtf-cfrg-spake2-08] that
  M: 'd048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf',
  N: 'd3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab',
  p: new BN('7237005577332262213973186563042994240857116359379907606001950938285454250989', 10),
  h: new BN(8)
}

/**
 * Enumerate the curves.
 *
 * @readonly
 * @enum {Curve}
 */
const CURVES = {
  ed25519: curveEd25519
}

class Elliptic {
  constructor (curve) {
    const ec = new EC(curve.name)
    this.name = curve.name
    this.ec = ec.curve
    this.M = this.decodePoint(curve.M)
    this.N = this.decodePoint(curve.N)
    this.P = this.ec.g
    this.p = curve.p
    this.h = curve.h
  }

  /**
   * ...
   *
   * @param {Buffer} buf ...
   * @returns {*} ...
   */
  decodePoint (buf) {
    if (this.name === 'ed25519') {
      const b = new BN(buf.toString('hex'), 16, 'le')
      // b = [x % 2 (1bit)][y (255bits)]
      return this.ec.pointFromY(b.mod(TWO_POW_255).toString(16), b.gte(TWO_POW_255))
    }
    return this.ec.decodePoint(buf, true)
  }

  /**
   * ...
   *
   * @param {*} p ...
   * @returns {Buffer} ...
   */
  encodePoint (p) {
    if (this.name === 'ed25519') {
      const x = p.getX()
      const y = p.getY()
      return x.mod(new BN(2)).mul(TWO_POW_255).add(y).toBuffer('le', 32)
    }
    return Buffer.from(p.encodeCompressed())
  }
}

module.exports = {
  CURVES,
  Elliptic
}
