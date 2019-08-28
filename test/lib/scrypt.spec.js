/* global describe, it */
const assert = require('assert')

const { scrypt } = require('../../src/lib/scrypt.js')

const testCases = [{
  password: Buffer.from(''),
  salt: Buffer.from(''),
  n: 16,
  r: 1,
  p: 1,
  hash: Buffer.from('77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906', 'hex')
}, {
  password: Buffer.from('password'),
  salt: Buffer.from('NaCl'),
  n: 1024,
  r: 8,
  p: 16,
  hash: Buffer.from('fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640', 'hex')
}, {
  password: Buffer.from('pleaseletmein'),
  salt: Buffer.from('SodiumChloride'),
  n: 16384,
  r: 8,
  p: 1,
  hash: Buffer.from('7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887', 'hex')
}]

describe('lib/scrypt.js', function () {
  describe('scrypt', function () {
    it('should hash inputs correctly', async function () {
      for (let index = 0; index < testCases.length; index++) {
        const testCase = testCases[index]
        const actualOutput = await scrypt(
          testCase.password, testCase.salt, testCase.n, testCase.r, testCase.p
        )
        assert.deepStrictEqual(actualOutput, testCase.hash)
      }
    })
  })
})
