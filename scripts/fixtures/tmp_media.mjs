import * as Crypto from 'node:crypto'
import { getMediaKeys, hkdfInfoKey } from '@whiskeysockets/baileys/lib/Utils/messages-media.js'

const mediaKey = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1))
const keys = await getMediaKeys(mediaKey, 'image')
const plaintext = Buffer.from('hello media')
const cipher = Crypto.createCipheriv('aes-256-cbc', keys.cipherKey, keys.iv)
const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
const mac = Crypto.createHmac('sha256', keys.macKey).update(keys.iv).update(ciphertext).digest().slice(0, 10)
console.log(JSON.stringify({
  info: hkdfInfoKey('image'),
  mediaKey: mediaKey.toString('hex'),
  iv: keys.iv.toString('hex'),
  cipherKey: keys.cipherKey.toString('hex'),
  macKey: keys.macKey.toString('hex'),
  plaintext: plaintext.toString('hex'),
  ciphertext: ciphertext.toString('hex'),
  mac: mac.toString('hex'),
  fileEncSha256: Crypto.createHash('sha256').update(Buffer.concat([ciphertext, mac])).digest('hex'),
}, null, 2))
