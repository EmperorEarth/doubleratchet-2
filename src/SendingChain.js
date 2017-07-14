import crypto from 'crypto'

import AbstractChain from './AbstractChain'
import Key from './Key'

import {
  ALGO_CIPHER,
} from './consts'

import {
  concatBuffers,
} from './utils'

export default class SendingChain extends AbstractChain {

  encrypt(data) {
    this.step()

    const cipher = crypto.createCipheriv(ALGO_CIPHER, this.messageKey.content, this.messageKey.iv)

    const cipherText = concatBuffers([
      cipher.update(data),
      cipher.final(),
    ])

    const header = this.makeHeader()

    const authenticationTag = this.makeAuthenticationTag([ header.cipherText, cipherText ])

    return concatBuffers([
      header.payload,
      authenticationTag,
      cipherText,
    ])
  }

  makeHeader() {
    const cipher = crypto.createCipheriv(ALGO_CIPHER, this.headerKey.content, this.headerKey.iv)

    const header = new Buffer(4 + this.ratchet.keys.ratchet.public.length)

    header.writeInt16LE(this.count, 0)
    header.writeInt16LE(this.previous, 2)
    this.ratchet.keys.ratchet.public.copy(header, 4)

    const cipherText = concatBuffers([
      cipher.update(header),
      cipher.final(),
    ])

    const payload = new Buffer(2 + cipherText.length)
    payload.writeInt16LE(cipherText.length, 0)
    cipherText.copy(payload, 2)

    return {
      cipherText,
      payload
    }
  }

}
