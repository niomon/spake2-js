/* global describe, it */
const assert = require('assert')

const { sha256 } = require('../../src/lib/hash.js')

const testCases = [{
  content: Buffer.from('input'),
  hash: Buffer.from('c96c6d5be8d08a12e7b5cdc1b207fa6b2430974c86803d8891675e76fd992c20', 'hex')
}, {
  content: Buffer.from('a quick brown fox jumps over the lazy dog'),
  hash: Buffer.from('8f1ad6dfff1a460eb4ab78a5a7c3576209628ea200c1dbc70bda69938b401309', 'hex')
}, {
  content: Buffer.from(''),
  hash: Buffer.from('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hex')
}]

describe('lib/mhf.js', function () {
  describe('sha256', function () {
    it('should hash inputs correctly', async function () {
      for (let index = 0; index < testCases.length; index++) {
        const testCase = testCases[index]
        const actualOutput = await sha256(testCase.content)
        assert.deepStrictEqual(actualOutput, testCase.hash)
      }
    })
  })
})
