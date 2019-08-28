const BN = require('bn.js')
const EC = require('elliptic').ec

const CURVES = {
  ed25519: {
    name: 'ed25519',
    // It is defined in [draft-irtf-cfrg-spake2-08] that
    // M := d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf and
    // N := d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab.
    M: {
      x: '1209a780 fc26087d aca42ec0 daa539de 37b3f303 982c1c35 1bbd6949 477e45e7',
      y: '2fcdcea5 66d1c6b0 e118bff1 20c9da3a a385da6b e8c2dd97 d6b6a06e 2c0348d0'
    },
    N: {
      x: '17bfe667 f20f5a89 2b153c2f 99906e4d ebc9087f 0d3a99d8 9cb3af55 6c27fc23',
      y: '2bc486f8 85ba68d8 5db369dc 8132eda1 653850af 920c9df2 30344ff4 18b5bfd3'
    },
    p: new BN('7237005577332262213973186563042994240857116359379907606001950938285454250989', 10),
    h: new BN(8)
  }
}

class Elliptic {
  constructor (curve) {
    const ec = new EC(curve.name)
    this.ec = ec.curve
    this.M = this.ec.point(curve.M.x, curve.M.y)
    this.N = this.ec.point(curve.N.x, curve.N.y)
    this.P = this.ec.g
    this.p = curve.p
    this.h = curve.h
  }
}

module.exports = {
  CURVES,
  Elliptic
}
