import crypto from 'crypto'

import Key from './Key'
import CipherKey from './CipherKey'

import {
  ALGO_HKDF_HMAC,
  AUTHENTICATION_KEY_LENGTH,
  CIPHER_IV_LENGTH,
  CIPHER_KEY_LENGTH,
} from './consts'

const DEFAULT_ALGO_HMAC = 'sha512'

export const hmac = (key, input, algo = DEFAULT_ALGO_HMAC) => {
  const hmac = crypto.createHmac(algo, key)
  hmac.update(input)
  return hmac.digest()
}

export const concatBuffers = (list) => {
  const length = list.reduce((a, c) => (a + c.length), 0)
  let buffer = new Buffer(length)
  let offset = 0
  for (let i = 0; i < list.length; i++) {
    offset += list[i].copy(buffer, offset)
  }
  return buffer
}

export const hkdf = (key, input, outputs, algo = ALGO_HKDF_HMAC) => {
  let _input = input
  if (input instanceof Key) {
    _input = input.content
  }
  for (var i = 0; i < outputs.length; i++) {
    if (outputs[i] instanceof CipherKey) {
      const keyMaterial = hmac(key.content, concatBuffers([ new Buffer(_input), new Buffer(outputs[i].type), new Buffer([ 1 ]) ]), algo)
      const ivMaterial = hmac(key.content, concatBuffers([ new Buffer(_input), new Buffer(outputs[i].type), new Buffer([ 2 ]) ]), algo)
      const authMaterial = hmac(key.content, concatBuffers([ new Buffer(_input), new Buffer(outputs[i].type), new Buffer([ 3 ]) ]), algo)
      outputs[i].content = keyMaterial.slice(0, CIPHER_KEY_LENGTH)
      outputs[i].iv = ivMaterial.slice(0, CIPHER_IV_LENGTH)
      outputs[i].auth = authMaterial.slice(0, AUTHENTICATION_KEY_LENGTH)
      key.content = new Buffer(keyMaterial)
    } else if (outputs[i] instanceof Key) {
      const keyMaterial = outputs[i].content = hmac(key.content, concatBuffers([ new Buffer(_input), new Buffer(outputs[i].type) ]), algo)
      key.content = new Buffer(keyMaterial)
    }
  }
  key.content = hmac(key.content, concatBuffers([ new Buffer(_input), new Buffer(key.type) ]), algo)
}

export const compare = (a, b) => {
  if (a !== null && b !== null) {
    if (a.length !== b.length) {
      return false
    }
  } else if ((a === null && b !== null) || (a !== null && b === null)) {
    return false
  }
  return crypto.timingSafeEqual(new Buffer(a ? a : []), new Buffer(b ? b : []))
}
