// Генерация золотых векторов эталонной реализацией Baileys.
// Запуск: cd scripts/fixtures && npm i && node gen_wabinary_fixtures.mjs
// Результат (tests/fixtures/wabinary/nodes.json) коммитится; в CI Node не нужен.
import { writeFileSync } from 'node:fs'
import { encodeBinaryNode } from '@whiskeysockets/baileys/lib/WABinary/encode.js'
import { decodeBinaryNode } from '@whiskeysockets/baileys/lib/WABinary/decode.js'

const B = (buffer) => ({ $binary: buffer.toString('base64') })
const bin = (text) => Buffer.from(text)

const cases = [
  {
    name: 'iq_with_child',
    node: {
      tag: 'iq',
      attrs: { id: '1', type: 'get', to: 's.whatsapp.net' },
      content: [{ tag: 'ping', attrs: {} }],
    },
  },
  {
    name: 'message_binary',
    node: {
      tag: 'message',
      attrs: { to: '491234567890@s.whatsapp.net', type: 'text' },
      content: bin('hello'),
    },
  },
  { name: 'presence', node: { tag: 'presence', attrs: { type: 'available' } } },
  {
    name: 'jid_with_device',
    node: {
      tag: 'message',
      attrs: { to: '491234567890:3@s.whatsapp.net', type: 'text' },
      content: bin('x'),
    },
  },
  {
    name: 'lid_jid',
    node: {
      tag: 'message',
      attrs: { to: '123456789012345@lid', type: 'text' },
      content: bin('x'),
    },
  },
  { name: 'nibble_odd', node: { tag: 'iq', attrs: { id: '12345' } } },
  { name: 'hex_string', node: { tag: 'iq', attrs: { id: 'ABCDEF' } } },
  { name: 'unicode_text', node: { tag: 'message', attrs: {}, content: 'привет' } },
  {
    name: 'nested_two_levels',
    node: {
      tag: 'iq',
      attrs: { id: 'a', type: 'set' },
      content: [
        {
          tag: 'list',
          attrs: {},
          content: [
            { tag: 'item', attrs: { n: '1' } },
            { tag: 'item', attrs: { n: '2' } },
          ],
        },
      ],
    },
  },
  { name: 'binary_300', node: { tag: 'enc', attrs: {}, content: Buffer.alloc(300, 7) } },
  {
    name: 'list_300',
    node: {
      tag: 'iq',
      attrs: {},
      content: Array.from({ length: 300 }, (_, index) => ({
        tag: 'item',
        attrs: { n: String(index) },
      })),
    },
  },
]

const toJson = (value) => {
  if (Buffer.isBuffer(value)) return B(value)
  if (typeof value === 'string') return value
  const node = { tag: value.tag, attrs: value.attrs }
  if (value.content !== undefined) {
    node.content = Array.isArray(value.content) ? value.content.map(toJson) : toJson(value.content)
  }
  return node
}

const fixtures = []
for (const { name, node } of cases) {
  const encoded = encodeBinaryNode(node)
  fixtures.push({
    name,
    node: toJson(node),
    hex: encoded.toString('hex'),
    decoded: toJson(await decodeBinaryNode(encoded)),
  })
}

writeFileSync(
  new URL('../../tests/fixtures/wabinary/nodes.json', import.meta.url),
  JSON.stringify(fixtures, null, 2) + '\n'
)
console.log(`Записано ${fixtures.length} фикстур`)
