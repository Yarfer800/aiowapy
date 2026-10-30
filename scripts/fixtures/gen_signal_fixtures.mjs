// Generate XEdDSA and protobuf vectors with the reference implementation.
// Usage: cd scripts/fixtures && npm i && node gen_signal_fixtures.mjs
import { writeFileSync, mkdirSync } from 'node:fs'
import * as curveJs from 'curve25519-js'
import { WhisperMessage, PreKeyWhisperMessage } from 'libsignal/src/protobufs.js'

mkdirSync(new URL('../../tests/fixtures/signal', import.meta.url), { recursive: true })

const keys = [
  Buffer.from(Array.from({ length: 32 }, (_, index) => index + 1)),
  Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex'),
]
const messages = [Buffer.alloc(0), Buffer.from('hello'), Buffer.alloc(100, 0x61)]

const xeddsa = []
for (const priv of keys) {
  const kp = curveJs.generateKeyPair(priv)
  const pub = Buffer.from(kp.public)
  for (const message of messages) {
    const signature = Buffer.from(curveJs.sign(priv, message))
    xeddsa.push({
      private: priv.toString('hex'),
      public: pub.toString('hex'),
      message: message.toString('hex'),
      signature: signature.toString('hex'),
    })
  }
}
writeFileSync(
  new URL('../../tests/fixtures/signal/xeddsa.json', import.meta.url),
  JSON.stringify(xeddsa, null, 2) + '\n'
)

const ephemeralKey = Buffer.concat([Buffer.from([5]), Buffer.alloc(32, 0x11)])
const ciphertext = Buffer.from('deadbeef', 'hex')
const whisper = WhisperMessage.create({ ephemeralKey, counter: 5, previousCounter: 2, ciphertext })
const whisperBytes = Buffer.from(WhisperMessage.encode(whisper).finish())
const baseKey = Buffer.concat([Buffer.from([5]), Buffer.alloc(32, 0x22)])
const identityKey = Buffer.concat([Buffer.from([5]), Buffer.alloc(32, 0x33)])
const prekey = PreKeyWhisperMessage.create({
  registrationId: 4242,
  preKeyId: 31337,
  signedPreKeyId: 7,
  baseKey,
  identityKey,
  message: whisperBytes,
})
const prekeyBytes = Buffer.from(PreKeyWhisperMessage.encode(prekey).finish())

writeFileSync(
  new URL('../../tests/fixtures/signal/protobuf.json', import.meta.url),
  JSON.stringify(
    {
      whisper: {
        fields: {
          ephemeralKey: ephemeralKey.toString('hex'),
          counter: 5,
          previousCounter: 2,
          ciphertext: ciphertext.toString('hex'),
        },
        hex: whisperBytes.toString('hex'),
      },
      prekey: {
        fields: {
          registrationId: 4242,
          preKeyId: 31337,
          signedPreKeyId: 7,
          baseKey: baseKey.toString('hex'),
          identityKey: identityKey.toString('hex'),
          message: whisperBytes.toString('hex'),
        },
        hex: prekeyBytes.toString('hex'),
      },
    },
    null,
    2
  ) + '\n'
)
console.log('Wrote signal vectors')
