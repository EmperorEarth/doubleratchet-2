
export default class Key {

  constructor(key, type = null) {
    if (key instanceof Key) {
      this.content = new Buffer(key.content)
      this.type = key.type
    } else {
      this.content = new Buffer(key || [])
      this.type = type
    }
  }

}
