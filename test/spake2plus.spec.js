/* global describe, it */
const assert = require('assert')

const spake2plus = require('../src/spake2plus')

describe('spake2plus', function () {
  it('should be able to finish authentication', function () {
    const identityA = 'client'
    const identityB = 'server'
    const partialPasswords = ['1337', '1337']
    const partialPassword = '1337'
    const passwordVerifier = '1337'

    const stateA = spake2plus.startA(identityA, identityB, partialPasswords)
    const stateB = spake2plus.startB(identityA, identityB, partialPassword, passwordVerifier)

    // A generates a message (X).
    const messageA = stateA.getMessage()

    // B verifies the message from A (X) and generates a message (Y).
    const sharedSecretB = stateB.finish(messageA)
    const messageB = stateB.getMessage()

    // A verifies the message from B (S).
    const sharedSecretA = stateA.finish(messageB)
    const confirmationA = sharedSecretA.getConfirmation()

    // B verifies the confirmation message (F) from A.
    assert.doesNotThrow(() => sharedSecretB.verify(confirmationA))
    const confirmationB = sharedSecretB.getConfirmation()

    // A verifies the confirmation message (F) from B.
    assert.doesNotThrow(() => sharedSecretA.verify(confirmationB))
  })
})
