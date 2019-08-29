/* global describe, it */
const assert = require('assert')

const spake2js = require('../src')

describe('index.js', function () {
  describe('SPAKE2', function () {
    describe('ED25519-SHA256-HKDF-HMAC-SCRYPT', function () {
      const testVector = {
        mhf: { n: 1024, r: 8, p: 16, salt: 'NaCl' },
        kdf: { AAD: '' },
        clientIdentity: 'client',
        serverIdentity: 'server',
        password: 'password',
        verifier: Buffer.from('fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162', 'hex')
      }
      it('should be able to finish authentication with correct confidentials', async function () {
        const { clientIdentity, serverIdentity, password, verifier: expectedVerifier } = testVector
        const { n, r, p, salt } = testVector.mhf
        const { kdf } = testVector

        const s = spake2js.spake2({ suite: 'ED25519-SHA256-HKDF-HMAC-SCRYPT', mhf: { n, p, r }, kdf })

        const verifier = await s.computeVerifier(password, salt)
        assert.deepStrictEqual(verifier, expectedVerifier)
        const stateA = await s.startClient(clientIdentity, serverIdentity, password, salt)
        const stateB = await s.startServer(clientIdentity, serverIdentity, verifier)

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

        // A and B have a common shared secret.
        assert.deepStrictEqual(sharedSecretA.toBuffer(), sharedSecretB.toBuffer())
      })
      it('should be able to finish authentication with correct confidentials using saves and loads', async function () {})
      it('should fail the authentication with T such that hT = I by the server', async function () {}) // TODO
      it('should fail the authentication with S such that hS = I by the client', async function () {}) // TODO
      it('should fail the authentication with wrong password by the server', async function () {
        const { clientIdentity, serverIdentity, verifier } = testVector
        const { n, r, p, salt } = testVector.mhf
        const { kdf } = testVector

        const s = spake2js.spake2({ suite: 'ED25519-SHA256-HKDF-HMAC-SCRYPT', mhf: { n, p, r }, kdf })

        const stateA = await s.startClient(clientIdentity, serverIdentity, 'a_wrong_password', salt)
        const stateB = await s.startServer(clientIdentity, serverIdentity, verifier)

        // A generates a message (X).
        const messageA = stateA.getMessage()

        // B verifies the message from A (X) and generates a message (Y).
        const messageB = stateB.getMessage()
        const sharedSecretB = stateB.finish(messageA)

        // A verifies the message from B (Y).
        const sharedSecretA = stateA.finish(messageB)
        const confirmationA = sharedSecretA.getConfirmation()

        // B verifies the confirmation message (F) from A - and fails.
        assert.throws(() => sharedSecretB.verify(confirmationA))
      })
      it('should fail the authentication with incorrect client identity by the server', async function () {
        const { clientIdentity, serverIdentity, password, verifier } = testVector
        const { n, r, p, salt } = testVector.mhf
        const { kdf } = testVector

        const s = spake2js.spake2({ suite: 'ED25519-SHA256-HKDF-HMAC-SCRYPT', mhf: { n, p, r }, kdf })

        const stateA = await s.startClient('another_client', serverIdentity, password, salt)
        const stateB = await s.startServer(clientIdentity, serverIdentity, verifier)

        // A generates a message (X).
        const messageA = stateA.getMessage()

        // B verifies the message from A (X) and generates a message (Y).
        const messageB = stateB.getMessage()
        const sharedSecretB = stateB.finish(messageA)

        // A verifies the message from B (Y).
        const sharedSecretA = stateA.finish(messageB)
        const confirmationA = sharedSecretA.getConfirmation()

        // B verifies the confirmation message (F) from A - and fails.
        assert.throws(() => sharedSecretB.verify(confirmationA))
      })
      it('should fail the authentication with incorrect server identity by the client', async function () {
        const { clientIdentity, serverIdentity, password, verifier } = testVector
        const { n, r, p, salt } = testVector.mhf
        const { kdf } = testVector

        const s = spake2js.spake2({ suite: 'ED25519-SHA256-HKDF-HMAC-SCRYPT', mhf: { n, p, r }, kdf })

        const stateA = await s.startClient(clientIdentity, serverIdentity, password, salt)
        const stateB = await s.startServer(clientIdentity, 'another_server', verifier)

        // A generates a message (X).
        const messageA = stateA.getMessage()

        // B verifies the message from A (X) and generates a message (Y).
        const messageB = stateB.getMessage()
        const sharedSecretB = stateB.finish(messageA)

        // A verifies the message from B (Y).
        const sharedSecretA = stateA.finish(messageB)

        // B sends the confirmation message (F) from A.
        const confirmationB = sharedSecretB.getConfirmation()

        // A verifies the confirmation message (F) from B - and fails.
        assert.throws(() => sharedSecretA.verify(confirmationB))
      })
    })
  })

  describe('SPAKE2+', function () {
    describe('ED25519-SHA256-HKDF-HMAC-SCRYPT', function () {
      const testVector = {
        mhf: { n: 1024, r: 8, p: 16, salt: 'NaCl' },
        kdf: { AAD: '' },
        clientIdentity: 'client',
        serverIdentity: 'server',
        password: 'password',
        verifier: {
          w0: Buffer.from('fdbabe1c9d3472007856e7190d01e9fe', 'hex'),
          L: Buffer.from('8b217c6a4b2a974931d910ebfbfa8614e83756a01274ba6a71cf90e7d84a5652', 'hex')
        }
      }
      it('should be able to finish authentication with correct confidentials', async function () {
        const { clientIdentity, serverIdentity, password, verifier: expectedVerifier } = testVector
        const { n, r, p, salt } = testVector.mhf
        const { kdf } = testVector

        const s = spake2js.spake2Plus({ suite: 'ED25519-SHA256-HKDF-HMAC-SCRYPT', mhf: { n, p, r }, kdf })

        const verifier = await s.computeVerifier(password, salt)
        assert.deepStrictEqual(verifier, expectedVerifier)
        const stateA = await s.startClient(clientIdentity, serverIdentity, password, salt)
        const stateB = await s.startServer(clientIdentity, serverIdentity, verifier)

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

        // A and B have a common shared secret.
        assert.deepStrictEqual(sharedSecretA.toBuffer(), sharedSecretB.toBuffer())
      })
      it('should fail the authentication with T such that hT = I by the server', async function () {}) // TODO
      it('should fail the authentication with S such that hS = I by the client', async function () {}) // TODO
      it('should fail the authentication with wrong password by the server', async function () {
        const { clientIdentity, serverIdentity, verifier } = testVector
        const { n, r, p, salt } = testVector.mhf
        const { kdf } = testVector

        const s = spake2js.spake2Plus({ suite: 'ED25519-SHA256-HKDF-HMAC-SCRYPT', mhf: { n, p, r }, kdf })

        const stateA = await s.startClient(clientIdentity, serverIdentity, 'a_wrong_password', salt)
        const stateB = await s.startServer(clientIdentity, serverIdentity, verifier)

        // A generates a message (X).
        const messageA = stateA.getMessage()

        // B verifies the message from A (X) and generates a message (Y).
        const messageB = stateB.getMessage()
        const sharedSecretB = stateB.finish(messageA)

        // A verifies the message from B (Y).
        const sharedSecretA = stateA.finish(messageB)
        const confirmationA = sharedSecretA.getConfirmation()

        // B verifies the confirmation message (F) from A - and fails.
        assert.throws(() => sharedSecretB.verify(confirmationA))
      })
      it('should fail the authentication with incorrect client identity by the server', async function () {
        const { clientIdentity, serverIdentity, password, verifier } = testVector
        const { n, r, p, salt } = testVector.mhf
        const { kdf } = testVector

        const s = spake2js.spake2Plus({ suite: 'ED25519-SHA256-HKDF-HMAC-SCRYPT', mhf: { n, p, r }, kdf })

        const stateA = await s.startClient('another_client', serverIdentity, password, salt)
        const stateB = await s.startServer(clientIdentity, serverIdentity, verifier)

        // A generates a message (X).
        const messageA = stateA.getMessage()

        // B verifies the message from A (X) and generates a message (Y).
        const messageB = stateB.getMessage()
        const sharedSecretB = stateB.finish(messageA)

        // A verifies the message from B (Y).
        const sharedSecretA = stateA.finish(messageB)
        const confirmationA = sharedSecretA.getConfirmation()

        // B verifies the confirmation message (F) from A - and fails.
        assert.throws(() => sharedSecretB.verify(confirmationA))
      })
      it('should fail the authentication with incorrect server identity by the client', async function () {
        const { clientIdentity, serverIdentity, password, verifier } = testVector
        const { n, r, p, salt } = testVector.mhf
        const { kdf } = testVector

        const s = spake2js.spake2Plus({ suite: 'ED25519-SHA256-HKDF-HMAC-SCRYPT', mhf: { n, p, r }, kdf })

        const stateA = await s.startClient(clientIdentity, serverIdentity, password, salt)
        const stateB = await s.startServer(clientIdentity, 'another_server', verifier)

        // A generates a message (X).
        const messageA = stateA.getMessage()

        // B verifies the message from A (X) and generates a message (Y).
        const messageB = stateB.getMessage()
        const sharedSecretB = stateB.finish(messageA)

        // A verifies the message from B (Y).
        const sharedSecretA = stateA.finish(messageB)

        // B sends the confirmation message (F) from A.
        const confirmationB = sharedSecretB.getConfirmation()

        // A verifies the confirmation message (F) from B - and fails.
        assert.throws(() => sharedSecretA.verify(confirmationB))
      })
    })
  })
})
