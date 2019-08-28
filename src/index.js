const crypto = require('crypto')
const BN = require('bn.js')

const { CURVES, Elliptic } = require('./lib/elliptic.js')
const { randomInteger } = require('./lib/random.js')
const { scrypt } = require('./lib/scrypt.js')

function concat (...args) {
  let o = Buffer.from([])
  for (const arg of args) {
    const argl = new BN(arg.length).toBuffer()
    o = Buffer.concat(
      [o, argl, arg],
      o.length + argl.length + arg.length
    )
  }
  return o
}

class SPAKE2 {
  constructor (options) {
    this.options = options
  }

  async startClient (clientIdentity, serverIdentity, password, salt) {
    const { options } = this
    const verifier = await this.computeVerifier(password, salt, false)

    const { p } = options.curve
    const x = randomInteger(new BN('0', 10), p) // uniformly generated in [0, p)
    if (!options.plus) {
      const w = new BN(verifier.toString('hex'), 16).mod(p)
      return new ClientSPAKE2State({ clientIdentity, serverIdentity, w, x, options })
    } else {
      const verifierLength = verifier.length
      const w0s = verifier.subarray(0, Math.floor(verifierLength / 2))
      const w1s = verifier.subarray(Math.floor(verifierLength / 2))
      const w0 = new BN(w0s.toString('hex'), 16).mod(p)
      const w1 = new BN(w1s.toString('hex'), 16).mod(p)
      return new ClientSPAKE2PlusState({ clientIdentity, serverIdentity, w0, w1, x, options })
    }
  }

  async startServer (clientIdentity, serverIdentity, verifier) {
    const { options } = this

    const { p } = options.curve
    const y = randomInteger(new BN('0', 10), p) // uniformly generated in [0, p)
    if (!options.plus) {
      const w = new BN(verifier.toString('hex'), 16).mod(p)
      return new ServerSPAKE2State({ clientIdentity, serverIdentity, w, y, options })
    } else {
      const { curve } = options
      const w0 = new BN(verifier.w0.toString('hex'), 16).mod(p)
      const L = curve.ec.decodePoint(verifier.L, true)
      return new ServerSPAKE2PlusState({ clientIdentity, serverIdentity, w0, L, y, options })
    }
  }

  async computeVerifier (password, salt, plus) {
    const { n, r, p } = this.options.scrypt
    const verifier = await scrypt(Buffer.from(password), Buffer.from(salt), n, r, p)
    if (!plus) return verifier

    const verifierLength = verifier.length
    const w0s = verifier.subarray(0, Math.floor(verifierLength / 2))
    const w1s = verifier.subarray(Math.floor(verifierLength / 2))
    const { options } = this
    const { P } = options.curve
    const L = P.mul(new BN(w1s.toString('hex'), 16))
    return {
      w0: w0s,
      L: Buffer.from(L.encodeCompressed())
    }
  }
}

class ClientSPAKE2State {
  constructor ({ clientIdentity, serverIdentity, w, x, options }) {
    this.options = options
    this.clientIdentity = clientIdentity
    this.serverIdentity = serverIdentity
    this.x = x
    this.w = w
  }

  getMessage () {
    const { options, x, w } = this
    const { P, M } = options.curve
    const T = P.mul(x).add(M.mul(w))
    this.T = T
    const message = Buffer.from(T.encodeCompressed())
    return message
  }

  finish (incomingMessage) {
    const { options } = this
    const { curve } = options
    const { h, N } = curve
    const S = curve.ec.decodePoint(incomingMessage, true)
    if (S.mul(h).isInfinity()) throw new Error('invalid curve point')
    const { clientIdentity, serverIdentity, T, w, x } = this
    const K = S.add(N.neg().mul(w)).mul(x)
    const TT = concat(Buffer.from(clientIdentity), Buffer.from(serverIdentity), Buffer.from(S.encode()), Buffer.from(T.encode()), Buffer.from(K.encode()), w.toBuffer())
    // TODO: use the hash algorithm defined by spec
    const hashTranscript = crypto.createHash('sha256').update(TT).digest()
    return new ClientSharedSecret({ options, transcript: TT, hashTranscript })
  }
}

class ServerSPAKE2State {
  constructor ({ clientIdentity, serverIdentity, w, y, options }) {
    this.options = options
    this.clientIdentity = clientIdentity
    this.serverIdentity = serverIdentity
    this.y = y
    this.w = w
  }

  getMessage () {
    const { options, y, w } = this
    const { P, N } = options.curve
    const S = P.mul(y).add(N.mul(w))
    this.S = S
    const message = Buffer.from(S.encodeCompressed())
    return message
  }

  finish (incomingMessage) {
    const { options } = this
    const { curve } = options
    const { h, M } = curve
    const T = curve.ec.decodePoint(incomingMessage, true)
    if (T.mul(h).isInfinity()) throw new Error('invalid curve point')
    const { clientIdentity, serverIdentity, S, w, y } = this
    const K = T.add(M.neg().mul(w)).mul(y)
    const TT = concat(Buffer.from(clientIdentity), Buffer.from(serverIdentity), Buffer.from(S.encode()), Buffer.from(T.encode()), Buffer.from(K.encode()), w.toBuffer())
    // TODO: use the hash algorithm defined by spec
    const hashTranscript = crypto.createHash('sha256').update(TT).digest()
    return new ServerSharedSecret({ options, transcript: TT, hashTranscript })
  }
}

class ClientSPAKE2PlusState {
  constructor ({ clientIdentity, serverIdentity, w0, w1, x, options }) {
    this.options = options
    this.clientIdentity = clientIdentity
    this.serverIdentity = serverIdentity
    this.x = x
    this.w0 = w0
    this.w1 = w1
  }

  getMessage () {
    const { options, x, w0 } = this
    const { P, M } = options.curve
    const T = P.mul(x).add(M.mul(w0))
    this.T = T
    const message = Buffer.from(T.encodeCompressed())
    return message
  }

  finish (incomingMessage) {
    const { options } = this
    const { curve } = options
    const { h, N } = curve
    const S = curve.ec.decodePoint(incomingMessage, true)
    if (S.mul(h).isInfinity()) throw new Error('invalid curve point')
    const { clientIdentity, serverIdentity, T, w0, w1, x } = this
    const Z = S.add(N.neg().mul(w0)).mul(x)
    const V = S.add(N.neg().mul(w0)).mul(w1)
    const TT = concat(Buffer.from(clientIdentity), Buffer.from(serverIdentity), Buffer.from(S.encode()), Buffer.from(T.encode()), Buffer.from(Z.encode()), Buffer.from(V.encode()), w0.toBuffer())
    // TODO: use the hash algorithm defined by spec
    const hashTranscript = crypto.createHash('sha256').update(TT).digest()
    return new ClientSharedSecret({ options, transcript: TT, hashTranscript })
  }
}

class ServerSPAKE2PlusState {
  constructor ({ clientIdentity, serverIdentity, w0, L, y, options }) {
    this.options = options
    this.clientIdentity = clientIdentity
    this.serverIdentity = serverIdentity
    this.y = y
    this.w0 = w0
    this.L = L
  }

  getMessage () {
    const { options, y, w0 } = this
    const { P, N } = options.curve
    const S = P.mul(y).add(N.mul(w0))
    this.S = S
    const message = Buffer.from(S.encodeCompressed())
    return message
  }

  finish (incomingMessage) {
    const { options } = this
    const { curve } = options
    const { h, M } = curve
    const T = curve.ec.decodePoint(incomingMessage, true)
    if (T.mul(h).isInfinity()) throw new Error('invalid curve point')
    const { clientIdentity, serverIdentity, S, w0, L, y } = this
    const Z = T.add(M.neg().mul(w0)).mul(y)
    const V = L.mul(y)
    const TT = concat(Buffer.from(clientIdentity), Buffer.from(serverIdentity), Buffer.from(S.encode()), Buffer.from(T.encode()), Buffer.from(Z.encode()), Buffer.from(V.encode()), w0.toBuffer())
    // TODO: use the hash algorithm defined by spec
    const hashTranscript = crypto.createHash('sha256').update(TT).digest()
    return new ServerSharedSecret({ options, transcript: TT, hashTranscript })
  }
}

class ClientSharedSecret {
  constructor ({ options, transcript, hashTranscript }) {
    this.options = options
    this.transcript = transcript
    this.hashTranscript = hashTranscript

    const transcriptLen = hashTranscript.length
    this.Ke = hashTranscript.subarray(0, Math.floor(transcriptLen / 2))
    this.Ka = hashTranscript.subarray(Math.floor(transcriptLen / 2))

    const Kc = crypto.createHmac('sha256', this.Ka).update(this.Ka).digest() // TODO: fix it
    const kcLen = Kc.length
    this.KcA = Kc.subarray(0, Math.floor(kcLen / 2))
    this.KcB = Kc.subarray(Math.floor(kcLen / 2))
  }

  getConfirmation () {
    const F = crypto.createHmac('sha256', this.KcA).update(this.transcript).digest()
    return F
  }

  verify (incomingConfirmation) {
    if (crypto.createHmac('sha256', this.KcB).update(this.transcript).digest().toString('hex') !== incomingConfirmation.toString('hex')) {
      throw new Error('invalid confirmation from server')
    }
  }

  toBuffer () {
    return this.Ke
  }
}

class ServerSharedSecret {
  constructor ({ options, transcript, hashTranscript }) {
    this.options = options
    this.transcript = transcript
    this.hashTranscript = hashTranscript

    const transcriptLen = hashTranscript.length
    this.Ke = hashTranscript.subarray(0, Math.floor(transcriptLen / 2))
    this.Ka = hashTranscript.subarray(Math.floor(transcriptLen / 2))

    const Kc = crypto.createHmac('sha256', this.Ka).update(this.Ka).digest() // TODO: fix it
    const kcLen = Kc.length
    this.KcA = Kc.subarray(0, Math.floor(kcLen / 2))
    this.KcB = Kc.subarray(Math.floor(kcLen / 2))
  }

  getConfirmation () {
    const F = crypto.createHmac('sha256', this.KcB).update(this.transcript).digest()
    return F
  }

  verify (incomingConfirmation) {
    if (crypto.createHmac('sha256', this.KcA).update(this.transcript).digest().toString('hex') !== incomingConfirmation.toString('hex')) {
      throw new Error('invalid confirmation from client')
    }
  }

  toBuffer () {
    return this.Ke
  }
}

function spake2 (options, plus) {
  options.plus = plus
  options.curve = new Elliptic(CURVES[options.curve])
  return new SPAKE2(options)
}

module.exports = {
  spake2: options => spake2(options, false),
  spake2Plus: options => spake2(options, true)
}
