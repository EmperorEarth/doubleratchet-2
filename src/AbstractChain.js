import crypto from 'crypto'

import Key from './Key'
import CipherKey from './CipherKey'

import {
  HKDF_KEY_TYPE_CHAIN,
  HKDF_KEY_TYPE_MESSAGE,
  HKDF_KEY_TYPE_HEADER,
  AUTHENTICATION_TAG_LENGTH,
} from './consts'

import {
  hkdf,
  hmac,
  concatBuffers,
} from './utils'

export default class AbstractChain {

  constructor(ratchet, headerKey = null, nextHeaderKey = null) {
    this.ratchet = ratchet
    this.keys = {
      chain:      new Key(null, HKDF_KEY_TYPE_CHAIN),
      message:    new CipherKey(null, null, null, HKDF_KEY_TYPE_MESSAGE),
      header:     new CipherKey(headerKey, null, null, HKDF_KEY_TYPE_HEADER),
      nextHeader: new CipherKey(nextHeaderKey, null, null, HKDF_KEY_TYPE_HEADER),
    }
    this.count = 0
    this.previous = 0
  }

  stepHkdf() {
    hkdf(this.keys.chain, this.keys.chain, [ this.keys.message ])
  }

  makeAuthenticationTag(elements, authKey = this.messageKey.auth) {
    return hmac(authKey, concatBuffers(elements)).slice(0, AUTHENTICATION_TAG_LENGTH)
  }

  step() {
    this.stepHkdf()
    this.count++
  }

  reset() {
    this._resetCounter()
    this._shiftHeaderKeys()
  }

  _resetCounter() {
    this.previous = this.count
    this.count = 0
  }

  _shiftHeaderKeys() {
    this.keys.header = new CipherKey(this.keys.nextHeader, null, null, HKDF_KEY_TYPE_HEADER)
    this.keys.nextHeader = new CipherKey(null, null, null, HKDF_KEY_TYPE_HEADER)
  }

  get chainKey() {
    return this.keys.chain
  }

  get chainKeyBuffer() {
    return new Buffer(this.keys.chain.content ? this.keys.chain.content : [])
  }

  get messageKey() {
    return this.keys.message
  }

  get messageKeyBuffer() {
    return new Buffer(this.keys.message.content ? this.keys.message.content : [])
  }

  get headerKey() {
    return this.keys.header
  }

  get headerKeyBuffer() {
    return new Buffer(this.keys.header.content ? this.keys.header.content : [])
  }

  get nextHeaderKey() {
    return this.keys.nextHeader
  }

  get nextHeaderKeyBuffer() {
    return new Buffer(this.keys.nextHeader.content ? this.keys.nextHeader.content : [])
  }

  getCoreState() {
    return {
      keys: {
        ...this.keys
      },
      count:    this.count,
      previous: this.previous,
    }
  }

  getState() {
    return this.getCoreState()
  }

}
