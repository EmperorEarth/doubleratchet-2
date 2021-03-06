const Ratchet = require('../dist').Ratchet

// agreed on between parties using ECDH, X3DH, physically, etc...
const preSharedKey__ROOT        = new Buffer('010061d5eb6946be4a77', 'hex')
const preSharedKey__header      = new Buffer('020061d5eb6946be4a77', 'hex')
const preSharedKey__nextHeader  = new Buffer('030061d5eb6946be4a77', 'hex')

const alice = new Ratchet(preSharedKey__ROOT, preSharedKey__header, preSharedKey__nextHeader)
const bob = new Ratchet(preSharedKey__ROOT, preSharedKey__nextHeader, preSharedKey__header)

// handshake sent over public channel
const bobHandshake = bob.makeHandshake()

alice.acceptHandshake(bobHandshake)

// initial message
console.log( bob.decrypt(alice.encrypt("ping")) )

console.log( alice.decrypt(bob.encrypt("pong")) )
