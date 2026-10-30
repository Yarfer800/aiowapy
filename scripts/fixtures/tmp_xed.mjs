import * as curveJs from 'curve25519-js'

const privs = [
  Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1)),
  Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex'),
]
const messages = [Buffer.alloc(0), Buffer.from('hello'), Buffer.alloc(100, 0x61)]
const out = []
for (const priv of privs) {
  const kp = curveJs.generateKeyPair(priv)
  const pub = Buffer.from(kp.public)
  for (const msg of messages) {
    const sig = Buffer.from(curveJs.sign(priv, msg))
    out.push({
      private: priv.toString('hex'),
      public: pub.toString('hex'),
      message: msg.toString('hex'),
      signature: sig.toString('hex'),
      verified: curveJs.verify(new Uint8Array(pub), new Uint8Array(msg), new Uint8Array(sig)),
    })
  }
}
console.log(JSON.stringify(out, null, 2))
