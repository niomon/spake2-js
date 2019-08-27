/* global describe, it */
const assert = require('assert')

const spake2 = require('../src/spake2')

describe('spake2', function () {
  it('should be able to finish authentication', function () {
    const identityA = 'client'
    const identityB = 'server'
    const password = '1337' // The shared password

    const stateA = spake2.startA(identityA, identityB, password)
    const stateB = spake2.startB(identityA, identityB, password)

    // A generates a message (T).
    const messageA = stateA.getMessage()

    // B verifies the message from A (T) and generates a message (S).
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
