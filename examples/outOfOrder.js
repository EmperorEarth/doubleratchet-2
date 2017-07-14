const Ratchet = require('../dist').Ratchet

// agreed on between parties using ECDH, X3DH, physically, etc...
const preSharedKey__ROOT        = new Buffer('010061d5eb6946be4a77', 'hex')
const preSharedKey__header      = new Buffer('020061d5eb6946be4a77', 'hex')
const preSharedKey__nextHeader  = new Buffer('030061d5eb6946be4a77', 'hex')

const alice = new Ratchet(preSharedKey__ROOT, preSharedKey__header, preSharedKey__nextHeader)
const bob = new Ratchet(preSharedKey__ROOT, preSharedKey__nextHeader, preSharedKey__header)

alice.acceptHandshake(bob.makeHandshake())

// initial message
console.log( bob.decrypt(alice.encrypt("initial message")) )

let messageId = 0

generateMessages()

setTimeout(generateMessages, 1000)
setTimeout(generateMessages, 2000)
setTimeout(generateMessages, 3000)
setTimeout(generateMessages, 4000)
setTimeout(generateMessages, 5000)

function generateMessages() {
  for (var i = 0; i < 50; i++) {
    if (Math.random() > 0.5) {
      deliver({
        payload:  alice.encrypt(`[alice]: this is message id ${messageId}`),
        to:       bob,
      })
    } else {
      deliver({
        payload:  bob.encrypt(`[bob]: this is message id ${messageId}`),
        to:       alice,
      })
    }
    messageId++
  }
}

function deliver(message) {
  setTimeout(function(){
    console.log(message.to.decrypt(message.payload))
  }, Math.random() * 10000)
}
