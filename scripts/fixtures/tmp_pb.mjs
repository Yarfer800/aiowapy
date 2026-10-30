import { WhisperMessage, PreKeyWhisperMessage } from 'libsignal/src/protobufs.js'

const ephemeralKey = Buffer.concat([Buffer.from([5]), Buffer.alloc(32, 0x11)])
const ciphertext = Buffer.from('deadbeef', 'hex')
const msg = WhisperMessage.create({ ephemeralKey, counter: 5, previousCounter: 2, ciphertext })
const msgBytes = WhisperMessage.encode(msg).finish()
const decoded = WhisperMessage.decode(msgBytes)

const pre = PreKeyWhisperMessage.create({
  registrationId: 4242,
  preKeyId: 31337,
  signedPreKeyId: 7,
  baseKey: Buffer.concat([Buffer.from([5]), Buffer.alloc(32, 0x22)]),
  identityKey: Buffer.concat([Buffer.from([5]), Buffer.alloc(32, 0x33)]),
  message: Buffer.from(msgBytes),
})
const preBytes = PreKeyWhisperMessage.encode(pre).finish()
const preDecoded = PreKeyWhisperMessage.decode(preBytes)

console.log(JSON.stringify({
  whisper: {
    fields: { ephemeralKey: ephemeralKey.toString('hex'), counter: 5, previousCounter: 2, ciphertext: ciphertext.toString('hex') },
    hex: Buffer.from(msgBytes).toString('hex'),
    decoded: { ephemeralKey: Buffer.from(decoded.ephemeralKey).toString('hex'), counter: decoded.counter, previousCounter: decoded.previousCounter, ciphertext: Buffer.from(decoded.ciphertext).toString('hex') },
  },
  prekey: {
    fields: { registrationId: 4242, preKeyId: 31337, signedPreKeyId: 7, baseKey: Buffer.concat([Buffer.from([5]), Buffer.alloc(32, 0x22)]).toString('hex'), identityKey: Buffer.concat([Buffer.from([5]), Buffer.alloc(32, 0x33)]).toString('hex'), message: Buffer.from(msgBytes).toString('hex') },
    hex: Buffer.from(preBytes).toString('hex'),
    decoded: { registrationId: preDecoded.registrationId, preKeyId: preDecoded.preKeyId, signedPreKeyId: preDecoded.signedPreKeyId, baseKey: Buffer.from(preDecoded.baseKey).toString('hex'), identityKey: Buffer.from(preDecoded.identityKey).toString('hex'), message: Buffer.from(preDecoded.message).toString('hex') },
  },
}, null, 2))
