import { generateLoginNode } from '@whiskeysockets/baileys/lib/Utils/validate-connection.js'
import { proto } from '@whiskeysockets/baileys/WAProto/index.js'

const config = {
  version: [2, 3000, 1043857760],
  browser: ['Mac OS', 'Chrome', '14.4.1'],
  syncFullHistory: false,
  countryCode: 'US',
  pushName: undefined,
}
const payload = generateLoginNode('79646669102:7@s.whatsapp.net', config)
console.log(Buffer.from(proto.ClientPayload.encode(payload).finish()).toString('hex'))
