const Ratchet = require('../dist').Ratchet

const preSharedKey__ROOT        = new Buffer('010061d5eb6946be4a77', 'hex')
const preSharedKey__header      = new Buffer('020061d5eb6946be4a77', 'hex')
const preSharedKey__nextHeader  = new Buffer('030061d5eb6946be4a77', 'hex')

const alice = new Ratchet(preSharedKey__ROOT, preSharedKey__header, preSharedKey__nextHeader)
const bob = new Ratchet(preSharedKey__ROOT, preSharedKey__nextHeader, preSharedKey__header)

const bobHandshake = bob.makeHandshake()

console.log(`[B] Handshake: ${bobHandshake.toString('hex')}`)

alice.acceptHandshake(bobHandshake)

const a1p = alice.encrypt('hello bob')

console.log(`[A]1 Payload: ${a1p.toString('hex')}`)

console.log(`[A]1 Plain: ${bob.decrypt(a1p)}`)

const b1p = bob.encrypt('hello alice, how are you?')

console.log(`[B]1 Payload: ${b1p.toString('hex')}`)

console.log(`[B]1 Plain: ${alice.decrypt(b1p)}`)

alice.encrypt("let's skip this 1")
alice.encrypt("let's skip this 2")
alice.encrypt("let's skip this 3")
alice.encrypt("let's skip this 4")
alice.encrypt("let's skip this 5")

console.log( bob.decrypt(alice.encrypt("hello???")) )

console.log( alice.decrypt(bob.encrypt("yo?")) )
