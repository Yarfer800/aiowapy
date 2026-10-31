import makeWASocket, { useMultiFileAuthState, Browsers } from '@whiskeysockets/baileys'
import { HttpsProxyAgent } from 'https-proxy-agent'
import pino from 'pino'
import qrcodeTerminal from 'qrcode-terminal'
import { appendFileSync, writeFileSync } from 'node:fs'

const LOG = '/tmp/opencode/baileys-trace.log'
writeFileSync(LOG, '')

const logger = pino({ level: 'trace' }, {
  write(line) {
    appendFileSync(LOG, line)
  },
})

const { state, saveCreds } = await useMultiFileAuthState('/tmp/baileys-trace-auth')
const sock = makeWASocket({
  auth: state,
  logger,
  browser: Browsers.ubuntu('Chrome'),
  printQRInTerminal: false,
  agent: new HttpsProxyAgent('http://127.0.0.1:10809'),
})

sock.ev.on('creds.update', saveCreds)
sock.ev.on('connection.update', (update) => {
  const { connection, qr, lastDisconnect } = update
  if (qr) {
    qrcodeTerminal.generate(qr, { small: true })
    console.log('SCAN: сканируйте код выше (живёт ~60с)')
  }
  if (connection === 'open') console.log('SCAN: соединение открыто (привязка принята)')
  if (connection === 'close') {
    console.log('SCAN: закрыто', lastDisconnect?.error?.output?.statusCode ?? '?')
    setTimeout(() => process.exit(0), 2000)
  }
})
setTimeout(() => { console.log('SCAN: таймаут'); process.exit(0) }, 120000)
