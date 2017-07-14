import crypto from 'crypto'

import AbstractChain from './AbstractChain'
import CipherKey from './CipherKey'

import {
  ALGO_CIPHER,
  AUTHENTICATION_TAG_LENGTH,
  MESSAGE_KEY_TTL,
} from './consts'

import {
  concatBuffers,
  compare,
} from './utils'

export default class ReceivingChain extends AbstractChain {

  constructor(ratchet, nextHeaderKey) {
    super(ratchet, null, nextHeaderKey)
    this.skipped = []
  }

  decryptHeader(cipherText) {
    if (this.headerKey) {
      const header = this._decryptHeader(cipherText, this.headerKey)
      if (header !== false) {
        return header
      }
    }
    if (this.nextHeaderKey) {
      const header = this._decryptHeader(cipherText, this.nextHeaderKey)
      if (header !== false) {
        return { ...header, usedNext: true }
      }
    }
    return false
  }

  _decryptHeader(cipherText, headerKey) {
    const output = this._decrypt(cipherText, headerKey)
    if (output !== false) {
      return {
        count:         output.readInt16LE(0),
        previous:      output.readInt16LE(2),
        ratchetKey:    output.slice(4),
      }
    }
    return false
  }

  decrypt(payload) {
    const {
      headerCipherText,
      cipherText,
      authenticationTag,
    } = this.deserialize(payload)

    const plainText = this.trySkipped(cipherText, headerCipherText, authenticationTag)

    if (plainText !== false) {
      return plainText
    }

    const header = this.decryptHeader(headerCipherText)

    if (header === false) {
      return false
    }

    const {
      count,
      previous,
      usedNext,
      ratchetKey,
    } = header

    let skipAfter = 0

    if (usedNext) {
      this.deleteOldKeys()
      this.skip(previous - this.count)
      this.ratchet.ratchet(ratchetKey)
      skipAfter = count
    } else {
      skipAfter = count - this.count
    }

    this.skip(skipAfter)

    if (!this.validAuthenticationTag(authenticationTag, headerCipherText, cipherText, this.messageKey.auth)) {
      return false
    }

    const output = this._decrypt(cipherText, this.messageKey)

    if (output !== false) {
      this.step()
      return output
    }

    return false
  }

  deserialize(data) {
    let offset = 0

    const headerLength = data.readInt16LE(0)
    offset += 2

    const headerCipherText = data.slice(offset, offset + headerLength)
    offset += headerLength

    const authenticationTag = data.slice(offset, offset + AUTHENTICATION_TAG_LENGTH)
    offset += AUTHENTICATION_TAG_LENGTH

    const cipherText = data.slice(offset)

    return {
      headerCipherText,
      cipherText,
      authenticationTag,
    }
  }

  skip(count) {
    if (count <= 0) {
      return 0
    }
    const until = count + this.count
    for (var i = this.count; i < until; i++) {
      this.skipped.push({
        header:   new CipherKey(this.headerKey),
        message:  new CipherKey(this.messageKey),
        missed:   0,
      })
      this.step()
    }
  }

  deleteOldKeys() {
    for (var i = 0; i < this.skipped.length; i++) {
      if (++this.skipped[i].missed > MESSAGE_KEY_TTL) {
        this.skipped.splice(i, 1)
      }
    }
  }

  trySkipped(cipherText, headerCipherText, authenticationTag) {
    for (var i = 0; i < this.skipped.length; i++) {
      if (!this.validAuthenticationTag(authenticationTag, headerCipherText, cipherText, this.skipped[i].message.auth)) {
        continue
      }
      const output = this._decrypt(cipherText, this.skipped[i].message)
      if (output === false) {
        continue
      }
      this.skipped.splice(i, 1)
      return output
    }
    return false
  }

  validAuthenticationTag(authenticationTag, headerCipherText, cipherText, authenticationKey) {
    return compare(authenticationTag, this.makeAuthenticationTag([headerCipherText, cipherText], authenticationKey))
  }

  _decrypt(data, key) {
    try {
      const decipher = crypto.createDecipheriv(ALGO_CIPHER, key.content, key.iv)
      return concatBuffers([
        decipher.update(data),
        decipher.final(),
      ])
    } catch (e) {
      return false
    }
  }

  getState() {
    return {
      skipped: this.skipped,
      ...super.getState()
    }
  }

}
