import crypto from 'crypto'

import SendingChain from './SendingChain'
import ReceivingChain from './ReceivingChain'
import Key from './Key'
import CipherKey from './CipherKey'

import {
  ALGO_ECDH_CURVE,
  HKDF_KEY_TYPE_ROOT,
} from './consts'

import {
  hkdf,
} from './utils'

export default class Ratchet {

  constructor(rootKey, headerKey, nextHeaderKey) {
    this.curve = crypto.createECDH(ALGO_ECDH_CURVE)
    this.keys = {
      root: new Key(rootKey, HKDF_KEY_TYPE_ROOT),
      ratchet: {
        public:   null,
        private:  null,
      },
    }
    this.chains = {
      sending:    new SendingChain(this, headerKey),
      receiving:  new ReceivingChain(this, nextHeaderKey),
    }
  }

  makeHandshake() {
    this.keys.ratchet.public = this.curve.generateKeys()
    this.keys.ratchet.private = this.curve.getPrivateKey()
    this.chains.sending.keys.nextHeader = new CipherKey(this.chains.sending.keys.header)

    hkdf(this.keys.root, this.keys.root, [ this.chains.receiving.nextHeaderKey, this.chains.sending.nextHeaderKey ])

    return this.keys.ratchet.public
  }

  acceptHandshake(key) {
    this.keys.ratchet.public = this.curve.generateKeys()
    this.keys.ratchet.private = this.curve.getPrivateKey()

    let secret = this.curve.computeSecret(key)

    hkdf(this.keys.root, this.keys.root, [ this.chains.sending.headerKey, this.chains.receiving.nextHeaderKey ])
    hkdf(this.keys.root, secret, [ this.chains.sending.chainKey, this.chains.sending.nextHeaderKey ])
  }

  ratchet(key = null) {
    this.chains.receiving.reset()

    hkdf(this.keys.root,
      this.curve.computeSecret(key),
      [ this.chains.receiving.chainKey, this.chains.receiving.nextHeaderKey ]
    )

    this.keys.ratchet.public = this.curve.generateKeys()
    this.keys.ratchet.private = this.curve.getPrivateKey()

    this.chains.sending.reset()

    hkdf(this.keys.root,
      this.curve.computeSecret(key),
      [ this.chains.sending.chainKey, this.chains.sending.nextHeaderKey ]
    )
  }

  encrypt(data) {
    return this.chains.sending.encrypt(data)
  }

  decryptBuffer(data) {
    return this.chains.receiving.decrypt(data)
  }

  decrypt(data) {
    const buffer = this.chains.receiving.decrypt(data)
    if (buffer === false) {
      return false
    }
    return buffer.toString()
  }
  
  getState() {
    return {
      receiving:  this.chains.receiving.getState(),
      sending:    this.chains.sending.getState(),
      root: {
        keys: {
          ...this.keys,
        }
      }
    }
  }

}
