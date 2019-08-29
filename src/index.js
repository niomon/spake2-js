const BN = require('bn.js')

const { CipherSuite, cipherSuites } = require('./lib/cipher-suites.js')
const { randomInteger } = require('./lib/random.js')

/**
 * Concatenates the buffers in the format `len(buf[0]) + buf[0] + len(buf[1]) + buf[1] + ...`.
 *
 * @private
 * @param  {...Buffer} bufs The buffers.
 * @returns {Buffer} The concatenated buffer.
 */
function concat (...bufs) {
  let outBuf = Buffer.from([])
  for (const buf of bufs) {
    const bufLen = new BN(buf.length).toBuffer()
    outBuf = Buffer.concat([outBuf, bufLen, buf], outBuf.length + bufLen.length + buf.length)
  }
  return outBuf
}

/**
 * Gets a cipher suite.
 *
 * @param {*} name The name of the cipher suite.
 * @returns {CipherSuite} The specified cipher suite.
 */
function getCipherSuite (name) {
  const cipherSuite = cipherSuites[name]
  if (!cipherSuite) throw new Error('undefined cipher suite')
  return cipherSuite
}

class SPAKE2 {
  constructor (options, cipherSuite) {
    this.options = options
    this.cipherSuite = cipherSuite
  }

  async startClient (clientIdentity, serverIdentity, password, salt) {
    const { options, cipherSuite } = this
    const verifier = await this.computeVerifier(password, salt, false)

    const { p } = cipherSuite.curve
    const x = randomInteger(new BN('0', 10), p) // uniformly generated in [0, p)
    if (!options.plus) {
      const w = new BN(verifier.toString('hex'), 16)
      return new ClientSPAKE2State({ clientIdentity, serverIdentity, w, x, options, cipherSuite })
    } else {
      const verifierLength = verifier.length
      const w0s = verifier.subarray(0, Math.floor(verifierLength / 2))
      const w1s = verifier.subarray(Math.floor(verifierLength / 2))
      const w0 = new BN(w0s.toString('hex'), 16).mod(p)
      const w1 = new BN(w1s.toString('hex'), 16).mod(p)
      return new ClientSPAKE2PlusState({ clientIdentity, serverIdentity, w0, w1, x, options, cipherSuite })
    }
  }

  async startServer (clientIdentity, serverIdentity, verifier) {
    const { options, cipherSuite } = this

    const { p } = cipherSuite.curve
    const y = randomInteger(new BN('0', 10), p) // uniformly generated in [0, p)
    if (!options.plus) {
      const w = new BN(verifier.toString('hex'), 16)
      return new ServerSPAKE2State({ clientIdentity, serverIdentity, w, y, options, cipherSuite })
    } else {
      const { curve } = cipherSuite
      const w0 = new BN(verifier.w0.toString('hex'), 16).mod(p)
      const L = curve.decodePoint(verifier.L)
      return new ServerSPAKE2PlusState({ clientIdentity, serverIdentity, w0, L, y, options, cipherSuite })
    }
  }

  async computeVerifier (password, salt, plus) {
    if (plus === undefined) plus = this.options.plus
    const { cipherSuite, options } = this
    const verifier = await cipherSuite.mhf(Buffer.from(password), Buffer.from(salt), options.mhf)
    if (!plus) return verifier

    const verifierLength = verifier.length
    const w0s = verifier.subarray(0, Math.floor(verifierLength / 2))
    const w1s = verifier.subarray(Math.floor(verifierLength / 2))
    const { P } = cipherSuite.curve
    const L = P.mul(new BN(w1s.toString('hex'), 16))
    return {
      w0: w0s,
      L: cipherSuite.curve.encodePoint(L)
    }
  }
}

class ClientSPAKE2State {
  constructor ({ clientIdentity, serverIdentity, w, x, options, cipherSuite }) {
    this.options = options
    this.cipherSuite = cipherSuite
    this.clientIdentity = clientIdentity
    this.serverIdentity = serverIdentity
    this.x = x
    this.w = w
  }

  getMessage () {
    const { cipherSuite, x, w } = this
    const { P, M } = cipherSuite.curve
    const T = P.mul(x).add(M.mul(w))
    this.T = T
    const message = cipherSuite.curve.encodePoint(T)
    return message
  }

  finish (incomingMessage) {
    const { cipherSuite, options } = this
    const { curve } = cipherSuite
    const { h, N } = curve
    const S = curve.decodePoint(incomingMessage)
    if (S.mul(h).isInfinity()) throw new Error('invalid curve point')
    const { clientIdentity, serverIdentity, T, w, x } = this
    const K = S.add(N.neg().mul(w)).mul(x)
    const TT = concat(Buffer.from(clientIdentity), Buffer.from(serverIdentity), curve.encodePoint(S), curve.encodePoint(T), curve.encodePoint(K), w.toBuffer())
    const hashTranscript = cipherSuite.hash(TT)
    return new ClientSharedSecret({ options, cipherSuite, transcript: TT, hashTranscript })
  }

  save () {
    const { options, x, w, clientIdentity, serverIdentity } = this
    return {
      options,
      x: x.toString('hex'),
      w: w.toString('hex'),
      clientIdentity,
      serverIdentity
    }
  }

  static load ({ options, x, w, clientIdentity, serverIdentity }) {
    let { suite } = options
    if (suite === undefined) suite = 'ED25519-SHA256-HKDF-HMAC-SCRYPT'
    const cipherSuite = getCipherSuite(suite)
    return new ClientSPAKE2State({ options, x: new BN(x, 16), w: new BN(w, 16), clientIdentity, serverIdentity, cipherSuite })
  }
}

class ServerSPAKE2State {
  constructor ({ clientIdentity, serverIdentity, w, y, options, cipherSuite }) {
    this.options = options
    this.cipherSuite = cipherSuite
    this.clientIdentity = clientIdentity
    this.serverIdentity = serverIdentity
    this.y = y
    this.w = w
  }

  getMessage () {
    const { cipherSuite, y, w } = this
    const { P, N } = cipherSuite.curve
    const S = P.mul(y).add(N.mul(w))
    this.S = S
    const message = cipherSuite.curve.encodePoint(S)
    return message
  }

  finish (incomingMessage) {
    const { options, cipherSuite } = this
    const { curve } = cipherSuite
    const { h, M } = curve
    const T = curve.decodePoint(incomingMessage)
    if (T.mul(h).isInfinity()) throw new Error('invalid curve point')
    const { clientIdentity, serverIdentity, S, w, y } = this
    const K = T.add(M.neg().mul(w)).mul(y)
    const TT = concat(Buffer.from(clientIdentity), Buffer.from(serverIdentity), curve.encodePoint(S), curve.encodePoint(T), curve.encodePoint(K), w.toBuffer())
    const hashTranscript = cipherSuite.hash(TT)
    return new ServerSharedSecret({ options, cipherSuite, transcript: TT, hashTranscript })
  }

  save () {
    const { options, y, w, clientIdentity, serverIdentity } = this
    return {
      options,
      y: y.toString('hex'),
      w: w.toString('hex'),
      clientIdentity,
      serverIdentity
    }
  }

  static load ({ options, y, w, clientIdentity, serverIdentity }) {
    let { suite } = options
    if (suite === undefined) suite = 'ED25519-SHA256-HKDF-HMAC-SCRYPT'
    const cipherSuite = getCipherSuite(suite)
    return new ServerSPAKE2State({ options, y: new BN(y, 16), w: new BN(w, 16), clientIdentity, serverIdentity, cipherSuite })
  }
}

class ClientSPAKE2PlusState {
  constructor ({ clientIdentity, serverIdentity, w0, w1, x, options, cipherSuite }) {
    this.options = options
    this.cipherSuite = cipherSuite
    this.clientIdentity = clientIdentity
    this.serverIdentity = serverIdentity
    this.x = x
    this.w0 = w0
    this.w1 = w1
  }

  getMessage () {
    const { cipherSuite, x, w0 } = this
    const { P, M } = cipherSuite.curve
    const T = P.mul(x).add(M.mul(w0))
    this.T = T
    const message = cipherSuite.curve.encodePoint(T)
    return message
  }

  finish (incomingMessage) {
    const { options, cipherSuite } = this
    const { curve } = cipherSuite
    const { h, N } = curve
    const S = curve.decodePoint(incomingMessage)
    if (S.mul(h).isInfinity()) throw new Error('invalid curve point')
    const { clientIdentity, serverIdentity, T, w0, w1, x } = this
    const Z = S.add(N.neg().mul(w0)).mul(x)
    const V = S.add(N.neg().mul(w0)).mul(w1)
    const TT = concat(Buffer.from(clientIdentity), Buffer.from(serverIdentity), Buffer.from(S.encode()), Buffer.from(T.encode()), Buffer.from(Z.encode()), Buffer.from(V.encode()), w0.toBuffer())
    const hashTranscript = cipherSuite.hash(TT)
    return new ClientSharedSecret({ options, transcript: TT, hashTranscript, cipherSuite })
  }

  save () {
    const { options, x, w0, w1, clientIdentity, serverIdentity } = this
    return {
      options,
      x: x.toString('hex'),
      w0: w0.toString('hex'),
      w1: w1.toString('hex'),
      clientIdentity,
      serverIdentity
    }
  }

  static load ({ options, x, w0, w1, clientIdentity, serverIdentity }) {
    let { suite } = options
    if (suite === undefined) suite = 'ED25519-SHA256-HKDF-HMAC-SCRYPT'
    const cipherSuite = getCipherSuite(suite)
    return new ClientSPAKE2PlusState({ options, x: new BN(x, 16), w0: new BN(w0, 16), w1: new BN(w1, 16), clientIdentity, serverIdentity, cipherSuite })
  }
}

class ServerSPAKE2PlusState {
  constructor ({ clientIdentity, serverIdentity, w0, L, y, options, cipherSuite }) {
    this.options = options
    this.cipherSuite = cipherSuite
    this.clientIdentity = clientIdentity
    this.serverIdentity = serverIdentity
    this.y = y
    this.w0 = w0
    this.L = L
  }

  getMessage () {
    const { cipherSuite, y, w0 } = this
    const { P, N } = cipherSuite.curve
    const S = P.mul(y).add(N.mul(w0))
    this.S = S
    const message = cipherSuite.curve.encodePoint(S)
    return message
  }

  finish (incomingMessage) {
    const { options, cipherSuite } = this
    const { curve } = cipherSuite
    const { h, M } = curve
    const T = curve.decodePoint(incomingMessage)
    if (T.mul(h).isInfinity()) throw new Error('invalid curve point')
    const { clientIdentity, serverIdentity, S, w0, L, y } = this
    const Z = T.add(M.neg().mul(w0)).mul(y)
    const V = L.mul(y)
    const TT = concat(Buffer.from(clientIdentity), Buffer.from(serverIdentity), Buffer.from(S.encode()), Buffer.from(T.encode()), Buffer.from(Z.encode()), Buffer.from(V.encode()), w0.toBuffer())
    const hashTranscript = cipherSuite.hash(TT)
    return new ServerSharedSecret({ options, transcript: TT, hashTranscript, cipherSuite })
  }

  save () {
    const { options, x, w0, L, clientIdentity, serverIdentity } = this
    return {
      options,
      x: x.toString('hex'),
      w0: w0.toString('hex'),
      L, // TODO
      clientIdentity,
      serverIdentity
    }
  }

  static load ({ options, x, w0, L, clientIdentity, serverIdentity }) {
    let { suite } = options
    if (suite === undefined) suite = 'ED25519-SHA256-HKDF-HMAC-SCRYPT'
    const cipherSuite = getCipherSuite(suite)
    return new ClientSPAKE2PlusState({ options, x: new BN(x, 16), w0: new BN(w0, 16), L, clientIdentity, serverIdentity, cipherSuite })
  }
}

class ClientSharedSecret {
  constructor ({ options, transcript, hashTranscript, cipherSuite }) {
    this.options = options
    this.cipherSuite = cipherSuite
    this.transcript = transcript
    this.hashTranscript = hashTranscript

    const transcriptLen = hashTranscript.length
    this.Ke = hashTranscript.subarray(0, Math.floor(transcriptLen / 2))
    this.Ka = hashTranscript.subarray(Math.floor(transcriptLen / 2))

    const Kc = cipherSuite.kdf('', this.Ka, 'ConfirmationKeys' || options.kdf.AAD)
    const kcLen = Kc.length
    this.KcA = Kc.subarray(0, Math.floor(kcLen / 2))
    this.KcB = Kc.subarray(Math.floor(kcLen / 2))
  }

  getConfirmation () {
    const { cipherSuite, transcript, KcA } = this
    const F = cipherSuite.mac(transcript, KcA)
    return F
  }

  verify (incomingConfirmation) {
    const { cipherSuite, transcript, KcB } = this
    if (cipherSuite.mac(transcript, KcB).toString('hex') !== incomingConfirmation.toString('hex')) {
      throw new Error('invalid confirmation from server')
    }
  }

  toBuffer () {
    return this.Ke
  }

  save () {
    const { options, transcript, hashTranscript } = this
    return {
      options,
      transcript,
      hashTranscript
    }
  }

  static load ({ options, transcript, hashTranscript }) {
    let { suite } = options
    if (suite === undefined) suite = 'ED25519-SHA256-HKDF-HMAC-SCRYPT'
    const cipherSuite = getCipherSuite(suite)
    return new ClientSharedSecret({ options, transcript, hashTranscript, cipherSuite })
  }
}

class ServerSharedSecret {
  constructor ({ options, transcript, hashTranscript, cipherSuite }) {
    this.options = options
    this.cipherSuite = cipherSuite
    this.transcript = transcript
    this.hashTranscript = hashTranscript

    const transcriptLen = hashTranscript.length
    this.Ke = hashTranscript.subarray(0, Math.floor(transcriptLen / 2))
    this.Ka = hashTranscript.subarray(Math.floor(transcriptLen / 2))

    const Kc = cipherSuite.kdf('', this.Ka, 'ConfirmationKeys' || options.kdf.AAD)
    const kcLen = Kc.length
    this.KcA = Kc.subarray(0, Math.floor(kcLen / 2))
    this.KcB = Kc.subarray(Math.floor(kcLen / 2))
  }

  getConfirmation () {
    const { cipherSuite, transcript, KcB } = this
    const F = cipherSuite.mac(transcript, KcB)
    return F
  }

  verify (incomingConfirmation) {
    const { cipherSuite, transcript, KcA } = this
    if (cipherSuite.mac(transcript, KcA).toString('hex') !== incomingConfirmation.toString('hex')) {
      throw new Error('invalid confirmation from client')
    }
  }

  toBuffer () {
    return this.Ke
  }

  save () {
    const { options, transcript, hashTranscript } = this
    return {
      options,
      transcript,
      hashTranscript
    }
  }

  static load ({ options, transcript, hashTranscript }) {
    let { suite } = options
    if (suite === undefined) suite = 'ED25519-SHA256-HKDF-HMAC-SCRYPT'
    const cipherSuite = getCipherSuite(suite)
    return new ServerSharedSecret({ options, transcript, hashTranscript, cipherSuite })
  }
}

/**
 * Creates a SPAKE2 instance.
 *
 * @param {object} options The options.
 * @param {string} options.suite The cipher suite used by the SPAKE2(+) instance.
 * @param {boolean} plus Uses SPAKE2+ if set to `true`. SPAKE2 otherwise.
 * @returns {SPAKE2} The SPAKE2 instance for authentication.
 */
function spake2 (options = {}, plus = false) {
  let { suite } = options
  if (suite === undefined) suite = 'ED25519-SHA256-HKDF-HMAC-SCRYPT'
  const cipherSuite = getCipherSuite(suite)
  options.plus = plus
  return new SPAKE2(options, cipherSuite)
}

module.exports = {
  spake2: options => spake2(options, false),
  spake2Plus: options => spake2(options, true),
  SPAKE2,
  ClientSPAKE2State,
  ServerSPAKE2State,
  ClientSPAKE2PlusState,
  ServerSPAKE2PlusState,
  ClientSharedSecret,
  ServerSharedSecret
}
