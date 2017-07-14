const Ratchet = require('../dist').Ratchet

// agreed on between parties using ECDH, X3DH, physically, etc...
const preSharedKey__ROOT        = new Buffer('010061d5eb6946be4a77', 'hex')
const preSharedKey__header      = new Buffer('020061d5eb6946be4a77', 'hex')
const preSharedKey__nextHeader  = new Buffer('030061d5eb6946be4a77', 'hex')

const alice = new Ratchet(preSharedKey__ROOT, preSharedKey__header, preSharedKey__nextHeader)
const bob = new Ratchet(preSharedKey__ROOT, preSharedKey__nextHeader, preSharedKey__header)

alice.setSendingExtraAuthenticationData([ 'username_bob' ])
alice.setReceivingExtraAuthenticationData([ 'username_alice' ])

bob.setSendingExtraAuthenticationData([ 'username_alice' ])
bob.setReceivingExtraAuthenticationData([ 'username_bob' ])

alice.acceptHandshake(bob.makeHandshake())

// initial message
console.log( bob.decrypt(alice.encrypt("ping")) )

console.log( alice.decrypt(bob.encrypt("pong")) )

bob.setSendingExtraAuthenticationData([ 'username_eve' ])

try {
  console.log( bob.decrypt(alice.encrypt("ping")) )
  console.log( alice.decrypt(bob.encrypt("pong")) )
} catch (e) {
  console.log('unable to decrypt')
}
