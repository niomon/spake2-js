/* global describe, it */
const assert = require('assert')
const BN = require('bn.js')

const { randomInteger } = require('../../src/lib/random.js')

describe('lib/random.js', function () {
  describe('randomInteger', function () {
    it('should generate random integers within the given bound', function () {
      const l = new BN('27')
      const r = new BN('31')
      for (let i = 0; i < 1000; i++) {
        const random = randomInteger(l, r)
        // Ensures that l <= random < r
        assert(random.gte(l) && random.lt(r))
      }
    })
    describe('should generate random integers uniformly', function () {
      it('under range [0, 256)', function () {
        const l = new BN('0')
        const r = new BN('256')
        const tally = new Array(256).fill(0)
        for (let j = 0; j < 65536; j++) {
          const random = randomInteger(l, r).toNumber()
          assert(random >= 0 && random < r)
          tally[random]++
        }
        // tally[i] ~ N(256, 255) for i = 0, 1, ..., 255
        for (let i = 0; i < 256; i++) {
          assert(
            256 - 80 <= tally[i] && tally[i] <= 256 + 80,
            `randomInteger(${l.toString(10)}, ${r.toString(10)}) = ${i} has ${tally[i]} copies, ` +
            `which should be within [${256 - 80}, ${256 + 80}]`
          )
        }
      })
      it('under range [0, 255)', function () {
        const l = new BN('0')
        const r = new BN('255')
        const tally = new Array(255).fill(0)
        for (let j = 0; j < 65025; j++) {
          const random = randomInteger(l, r).toNumber()
          assert(random >= 0 && random < r)
          tally[random]++
        }
        // tally[i] ~ N(255, 254) for i = 0, 1, ..., 254
        for (let i = 0; i < 255; i++) {
          assert(
            255 - 80 <= tally[i] && tally[i] <= 255 + 80,
            `randomInteger(${l.toString(10)}, ${r.toString(10)}) = ${i} has ${tally[i]} copies, ` +
            `which should be within [${255 - 80}, ${255 + 80}]`
          )
        }
      })
    })
  })
})
