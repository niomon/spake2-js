/* global describe, it */
const assert = require('assert')

const { scrypt } = require('../../src/lib/mhf.js')

const testCases = [{
  password: Buffer.from(''),
  salt: Buffer.from(''),
  options: { n: 16, r: 1, p: 1 },
  hash: Buffer.from('77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442', 'hex')
}, {
  password: Buffer.from('password'),
  salt: Buffer.from('NaCl'),
  options: { n: 1024, r: 8, p: 16 },
  hash: Buffer.from('fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162', 'hex')
}, {
  password: Buffer.from('pleaseletmein'),
  salt: Buffer.from('SodiumChloride'),
  options: { n: 16384, r: 8, p: 1 },
  hash: Buffer.from('7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2', 'hex')
}]

describe('lib/mhf.js', function () {
  describe('scrypt', function () {
    it('should hash inputs correctly', async function () {
      for (let index = 0; index < testCases.length; index++) {
        const testCase = testCases[index]
        const actualOutput = await scrypt(testCase.password, testCase.salt, testCase.options)
        assert.deepStrictEqual(actualOutput, testCase.hash)
      }
    })
  })
})
