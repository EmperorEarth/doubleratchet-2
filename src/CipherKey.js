import Key from './Key'

export default class CipherKey extends Key {

  constructor(key, iv = null, auth = null, type = null) {
    if (key instanceof Key) {
      super(key)
    } else {
      super(key, type)
    }
    if (key instanceof CipherKey) {
      this.iv = new Buffer(key.iv)
      this.auth = new Buffer(key.auth)
    } else {
      this.iv = new Buffer(iv || [])
      this.auth = new Buffer(auth || [])
    }
  }

  nullify() {
    super.nullify()
    this.iv = null
    this.auth = null
  }

}
