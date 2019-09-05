/* global describe, it */
const assert = require('assert')
const BN = require('bn.js')

const spake2js = require('../../../src')
const fixture = require('./../../fixture.json')

describe('index.js', function () {
  describe('SPAKE2+', function () {
    describe('ED25519-SHA256-HKDF-HMAC-SCRYPT', function () {
      const testVector = {
        mhf: { n: 16, r: 1, p: 1, salt: 'NaCl' },
        kdf: { AAD: '' },
        clientIdentity: 'client',
        serverIdentity: 'server',
        password: 'password'
      }
      it('should be able to finish authentication with correct confidentials', async function () {
        const { clientIdentity, serverIdentity, password, kdf } = testVector
        const { n, r, p, salt } = testVector.mhf

        const s = spake2js.spake2Plus({ suite: 'ED25519-SHA256-HKDF-HMAC-SCRYPT', mhf: { n, p, r }, kdf })

        const verifier = await s.computeVerifier(password, salt, clientIdentity, serverIdentity)
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
      it('should be able to finish authentication with correct confidentials using saves and loads', async function () {
        const { clientIdentity, serverIdentity, password, kdf } = testVector
        const { n, r, p, salt } = testVector.mhf

        const s = spake2js.spake2Plus({ suite: 'ED25519-SHA256-HKDF-HMAC-SCRYPT', mhf: { n, p, r }, kdf })

        const verifier = await s.computeVerifier(password, salt, clientIdentity, serverIdentity)
        const oldStateA = await s.startClient(clientIdentity, serverIdentity, password, salt)
        const oldStateB = await s.startServer(clientIdentity, serverIdentity, verifier)

        // A and B save the states from the object.
        const stateAObject = oldStateA.save()
        const stateBObject = oldStateB.save()

        // A and B load the states from the object.
        const stateA = spake2js.ClientSPAKE2PlusState.load(stateAObject)
        const stateB = spake2js.ServerSPAKE2PlusState.load(stateBObject)

        // A generates a message (X).
        const messageA = stateA.getMessage()

        // B verifies the message from A (X) and generates a message (Y).
        const messageB = stateB.getMessage()
        const oldSharedSecretB = stateB.finish(messageA)

        // A verifies the message from B (Y).
        const oldSharedSecretA = stateA.finish(messageB)
        const confirmationA = oldSharedSecretA.getConfirmation()

        // A and B save the states from the object.
        const sharedSecretAObject = oldSharedSecretA.save()
        const sharedSecretBObject = oldSharedSecretB.save()

        // A and B load the states from the object.
        const sharedSecretA = spake2js.ClientSharedSecret.load(sharedSecretAObject)
        const sharedSecretB = spake2js.ServerSharedSecret.load(sharedSecretBObject)

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
        const { clientIdentity, serverIdentity, password, kdf } = testVector
        const { n, r, p, salt } = testVector.mhf

        const s = spake2js.spake2Plus({ suite: 'ED25519-SHA256-HKDF-HMAC-SCRYPT', mhf: { n, p, r }, kdf })

        const verifier = await s.computeVerifier(password, salt, clientIdentity, serverIdentity)
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
        const { clientIdentity, serverIdentity, password, kdf } = testVector
        const { n, r, p, salt } = testVector.mhf

        const s = spake2js.spake2Plus({ suite: 'ED25519-SHA256-HKDF-HMAC-SCRYPT', mhf: { n, p, r }, kdf })

        const verifier = await s.computeVerifier(password, salt, clientIdentity, serverIdentity)
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
        const { clientIdentity, serverIdentity, password, kdf } = testVector
        const { n, r, p, salt } = testVector.mhf

        const s = spake2js.spake2Plus({ suite: 'ED25519-SHA256-HKDF-HMAC-SCRYPT', mhf: { n, p, r }, kdf })

        const verifier = await s.computeVerifier(password, salt, clientIdentity, serverIdentity)
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
      it('should be able to process the test vectors', async function () {
        const testVectors = fixture['SPAKE2+']['ED25519-SHA256-HKDF-HMAC-SCRYPT']
        for (let i = 0; i < testVectors.length; i++) {
          const testVector = testVectors[i]

          const { clientIdentity, serverIdentity, password, kdf } = testVector
          const { n, r, p, salt } = testVector.mhf
          const x = new BN(testVector.x, 16)
          const y = new BN(testVector.y, 16)
          const expectedVerifier = {
            w0: Buffer.from(testVector.verifier.w0, 'hex'),
            L: Buffer.from(testVector.verifier.L, 'hex')
          }
          const expectedMessageA = Buffer.from(testVector.messageA, 'hex')
          const expectedMessageB = Buffer.from(testVector.messageB, 'hex')
          const expectedTranscript = Buffer.from(testVector.transcript, 'hex')
          const expectedHashTranscript = Buffer.from(testVector.hashTranscript, 'hex')
          const expectedConfirmationA = Buffer.from(testVector.confirmationA, 'hex')
          const expectedConfirmationB = Buffer.from(testVector.confirmationB, 'hex')
          const expectedSharedSecret = Buffer.from(testVector.sharedSecret, 'hex')

          const s = spake2js.spake2Plus({ suite: 'ED25519-SHA256-HKDF-HMAC-SCRYPT', mhf: { n, p, r }, kdf })

          const verifier = await s.computeVerifier(password, salt, clientIdentity, serverIdentity)
          assert.deepStrictEqual(verifier, expectedVerifier)
          const oldStateA = await s.startClient(clientIdentity, serverIdentity, password, salt)
          const oldStateB = await s.startServer(clientIdentity, serverIdentity, verifier)

          // A and B save the states from the object.
          const stateAObject = oldStateA.save()
          const stateBObject = oldStateB.save()

          // Inject the values of x and y.
          stateAObject.x = x.toString(16)
          stateBObject.y = y.toString(16)

          // A and B load the states from the object.
          const stateA = spake2js.ClientSPAKE2PlusState.load(stateAObject)
          const stateB = spake2js.ServerSPAKE2PlusState.load(stateBObject)

          // A generates a message (X).
          const messageA = stateA.getMessage()
          assert.deepStrictEqual(messageA, expectedMessageA)

          // B verifies the message from A (X) and generates a message (Y).
          const messageB = stateB.getMessage()
          const sharedSecretB = stateB.finish(messageA)
          assert.deepStrictEqual(messageB, expectedMessageB)

          const { transcript: transcriptB, hashTranscript: hashTranscriptB } = sharedSecretB
          assert.deepStrictEqual(transcriptB, expectedTranscript)
          assert.deepStrictEqual(hashTranscriptB, expectedHashTranscript)

          // A verifies the message from B (Y).
          const sharedSecretA = stateA.finish(messageB)
          const confirmationA = sharedSecretA.getConfirmation()
          assert.deepStrictEqual(confirmationA, expectedConfirmationA)

          const { transcript: transcriptA, hashTranscript: hashTranscriptA } = sharedSecretA
          assert.deepStrictEqual(transcriptA, expectedTranscript)
          assert.deepStrictEqual(hashTranscriptA, expectedHashTranscript)

          // B verifies the confirmation message (F) from A.
          assert.doesNotThrow(() => sharedSecretB.verify(confirmationA))
          const confirmationB = sharedSecretB.getConfirmation()
          assert.deepStrictEqual(confirmationB, expectedConfirmationB)

          // A verifies the confirmation message (F) from B.
          assert.doesNotThrow(() => sharedSecretA.verify(confirmationB))

          // A and B have a common shared secret.
          assert.deepStrictEqual(sharedSecretA.toBuffer(), sharedSecretB.toBuffer())
          assert.deepStrictEqual(sharedSecretA.toBuffer(), expectedSharedSecret)
        }
      })
    })
  })
})
