/* global describe, it */
const assert = require('assert')

const spake2js = require('../src')

describe('index.js', function () {
  it('should be able to finish authentication with SPAKE2', async function () {
    const n = 1024
    const r = 8
    const p = 16
    const identityA = 'client'
    const identityB = 'server'
    const password = 'password'
    const salt = 'NaCl'
    const expectedVerifier = Buffer.from('fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640', 'hex')

    const s = spake2js.spake2({ curve: 'ed25519', scrypt: { n, p, r } })

    const verifier = await s.computeVerifier(password, salt)
    assert.deepStrictEqual(verifier, expectedVerifier)
    const stateA = await s.startClient(identityA, identityB, password, salt)
    const stateB = await s.startServer(identityA, identityB, verifier)

    // A generates a message (X).
    const messageA = stateA.getMessage()

    // B verifies the message from A (X) and generates a message (Y).
    const messageB = stateB.getMessage()
    const sharedSecretB = stateB.finish(messageA)

    // A verifies the message from B (Y).
    const sharedSecretA = stateA.finish(messageB)
    const confirmationA = sharedSecretA.getConfirmation()

    // B verifies the confirmation message (F) from A.
    assert.doesNotThrow(() => sharedSecretB.verify(confirmationA))
    const confirmationB = sharedSecretB.getConfirmation()

    // A verifies the confirmation message (F) from B.
    assert.doesNotThrow(() => sharedSecretA.verify(confirmationB))
  })

  it('should be able to finish authentication with SPAKE2+', async function () {
    const n = 1024
    const r = 8
    const p = 16
    const identityA = 'client'
    const identityB = 'server'
    const password = 'password'
    const salt = 'NaCl'
    const expectedVerifier = {
      w0: Buffer.from('fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162', 'hex'),
      L: Buffer.from('026823b5f9fef2f0d3e0099231d9bad97aa07cb2a0e8e9aaffe36da2e57b747326', 'hex')
    }

    const s = spake2js.spake2Plus({ curve: 'ed25519', scrypt: { n, p, r } })

    const verifier = await s.computeVerifier(password, salt, true)
    assert.deepStrictEqual(verifier, expectedVerifier)
    const stateA = await s.startClient(identityA, identityB, password, salt)
    const stateB = await s.startServer(identityA, identityB, verifier)

    // A generates a message (X).
    const messageA = stateA.getMessage()

    // B verifies the message from A (X) and generates a message (Y).
    const messageB = stateB.getMessage()
    const sharedSecretB = stateB.finish(messageA)

    // A verifies the message from B (Y).
    const sharedSecretA = stateA.finish(messageB)
    const confirmationA = sharedSecretA.getConfirmation()

    // B verifies the confirmation message (F) from A.
    assert.doesNotThrow(() => sharedSecretB.verify(confirmationA))
    const confirmationB = sharedSecretB.getConfirmation()

    // A verifies the confirmation message (F) from B.
    assert.doesNotThrow(() => sharedSecretA.verify(confirmationB))
  })
})
