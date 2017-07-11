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
    const cipher = crypto.createCipheriv(ALGO_CIPHER, this.messageKey.content, this.messageKey.iv)

    const cipherText = concatBuffers([
      cipher.update(data),
      cipher.final(),
    ])

    const header = this.makeHeader()

    const authenticationTag = this.makeAuthenticationTag(header, cipherText)

    this.step()

    return concatBuffers([
      header,
      this.ratchet.keys.ratchet.public,
      authenticationTag,
      cipherText,
    ])
  }

  makeHeader() {
    const cipher = crypto.createCipheriv(ALGO_CIPHER, this.headerKey.content, this.headerKey.iv)

    const header = Buffer.allocUnsafe(4)
    header.writeInt16LE(this.count, 0)
    header.writeInt16LE(this.previous, 2)

    return concatBuffers([
      cipher.update(header),
      cipher.final(),
    ])
  }

}
