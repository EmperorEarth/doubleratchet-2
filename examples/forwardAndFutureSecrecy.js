const Ratchet = require('../dist').Ratchet

// agreed on between parties using ECDH, X3DH, physically, etc...
const preSharedKey__ROOT        = new Buffer('010061d5eb6946be4a77', 'hex')
const preSharedKey__header      = new Buffer('020061d5eb6946be4a77', 'hex')
const preSharedKey__nextHeader  = new Buffer('030061d5eb6946be4a77', 'hex')

const alice1 = new Ratchet(preSharedKey__ROOT, preSharedKey__header, preSharedKey__nextHeader)
const bob1 = new Ratchet(preSharedKey__ROOT, preSharedKey__nextHeader, preSharedKey__header)

alice1.acceptHandshake(bob1.makeHandshake())

// initial message
console.log( bob1.decrypt(alice1.encrypt("ping")) )

const bobMessage1 = bob1.encrypt("you can only decrypt this once")

try {
  console.log( alice1.decrypt(bobMessage1) )
  console.log( alice1.decrypt(bobMessage1) )
} catch (e) {
  console.log('unable to decrypt')
}


// todo - reverse, need state snapshot complete first
