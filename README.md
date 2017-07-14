# DoubleRatchet

This is a mostly complete implementation of the Encrypted Header variant of the [The Double Ratchet Algorithm](https://whispersystems.org/docs/specifications/doubleratchet/#ref-rfc2315) designed by [Open Whisper Systems](https://whispersystems.org).

**WARNING:** This implementation was created for learning purposes and should not be used outside of a development environment. Any concerns or suggestions are **very** welcome.

This implementation was built using the NodeJS `crypto` library as its only dependency. I decided to do this as [Electron](https://github.com/electron/electron) is the intended usage. However, it would be trivial to abstract the crypto provider in order to make this library browser friendly.

### Usage

```js
const Ratchet = require('doubleratchet').Ratchet

const pskRoot        = ... // a shared secret between alice and bob
const pskHeader      = ... // a shared secret between alice and bob
const pskNextHeader  = ... // a shared secret between alice and bob

const alice = new Ratchet(pskRoot, pskHeader, pskNextHeader)
const bob = new Ratchet(pskRoot, pskNextHeader, pskHeader)

alice.acceptHandshake( bob.makeHandshake() )

bob.decrypt( alice.encrypt('hello bob') )   // "hello bob"
alice.decrypt( bob.encrypt('hello alice') ) // "hello alice"
```

See `examples` directory for more.

### Development
```
git clone https://github.com/jowy/doubleratchet.git
cd doubleratchet 
yarn install
yarn build
```

### Implementation Parameters

| Parameter | Implementation |
| -------- | -------- |
| Ratchet ECDH Curve | `secp521r1` |
| HMAC-KDF (HKDF) | SHA256 |
| Header Cipher | AES256 CBC Mode |
| Header Key Derivation | Salted HKDF |
| Header Key Length | 32 Bytes (Truncated) |
| Header IV Derivation | Salted HKDF |
| Message Cipher | AES256 CBC Mode |
| Message Key Derivation | Salted HKDF |
| Message Key Length | 32 Bytes (Truncated) |
| Message IV Derivation | Salted HKDF |
| Auth Tag Derivation | Salted HKDF |
| Auth Key Length | 32 Bytes (Truncated) |
| Auth Tag Length | 16 Bytes (Truncated) |
| Skipped Message Key Expire Method | Ratchet Invocation |
| Skipped Message Key TTL | 20 |

### TODO

- flow typing
- comments
- tests
- clean up (H)KDF flow
- clean up `Key` and `CipherKey` initialization and handling
- clean up buffer handling
- state (de)serialization
- fix header & nextHeader initialization and flow
- proper handling of input & output encoding
- revise `CipherKey` kdf
- error handling for various things
- rollback chain state on failure
- more examples demonstrating various features of the protocol
