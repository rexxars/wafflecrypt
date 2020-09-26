import {stringToArrayBuffer} from '../src/browser/buffer'
import * as node from '../src/node'
import * as browser from '../src/browser'

const testString = 'Sample input data!'
const testNodeBuffer = Buffer.from(testString)
const testBrowserBuffer = stringToArrayBuffer(testString)

// BROWSER GENERATED KEY
describe('browser-generated jwk key', () => {
  let keys: browser.JwkKeyPair

  beforeAll(async () => {
    keys = await browser.generateKeyPair({type: 'jwk'})
  })

  test('encrypt in browser, decrypt in node', async () => {
    const encrypted = await browser.encrypt(keys.publicKey, testBrowserBuffer)
    const decrypted = await node.decrypt(keys.privateKey, Buffer.from(encrypted))
    expect(decrypted.equals(testNodeBuffer))
  })

  test('encrypt in node, decrypt in browser', async () => {
    const encrypted = await node.encrypt(keys.publicKey, testNodeBuffer)
    const decrypted = await browser.decrypt(keys.privateKey, Buffer.from(encrypted))
    expect(decrypted).toEqual(testBrowserBuffer)
  })
})

describe('browser-generated pem key', () => {
  let keys: browser.PemKeyPair

  beforeAll(async () => {
    keys = await browser.generateKeyPair({type: 'pem'})
  })

  test('encrypt in browser, decrypt in node', async () => {
    const encrypted = await browser.encrypt(keys.publicKey, testBrowserBuffer)
    const decrypted = await node.decrypt(keys.privateKey, Buffer.from(encrypted))
    expect(decrypted.equals(testNodeBuffer))
  })

  test('encrypt in node, decrypt in browser', async () => {
    const encrypted = await node.encrypt(keys.publicKey, testNodeBuffer)
    const decrypted = await browser.decrypt(keys.privateKey, Buffer.from(encrypted))
    expect(decrypted).toEqual(testBrowserBuffer)
  })
})

describe('browser-generated mixed key', () => {
  let keys: browser.KeyPair

  beforeAll(async () => {
    keys = await browser.generateKeyPair()
  })

  test('encrypt in browser with jwk, decrypt in node with pem', async () => {
    const encrypted = await browser.encrypt(keys.jwk.publicKey, testBrowserBuffer)
    const decrypted = await node.decrypt(keys.pem.privateKey, Buffer.from(encrypted))
    expect(decrypted.equals(testNodeBuffer))
  })

  test('encrypt in browser with pem, decrypt in node with jwk', async () => {
    const encrypted = await browser.encrypt(keys.pem.publicKey, testBrowserBuffer)
    const decrypted = await node.decrypt(keys.jwk.privateKey, Buffer.from(encrypted))
    expect(decrypted.equals(testNodeBuffer))
  })

  test('encrypt in node with jwk, decrypt in browser with pem', async () => {
    const encrypted = await node.encrypt(keys.jwk.publicKey, testNodeBuffer)
    const decrypted = await browser.decrypt(keys.pem.privateKey, Buffer.from(encrypted))
    expect(decrypted).toEqual(testBrowserBuffer)
  })

  test('encrypt in node with pem, decrypt in browser with jwk', async () => {
    const encrypted = await node.encrypt(keys.pem.publicKey, testNodeBuffer)
    const decrypted = await browser.decrypt(keys.jwk.privateKey, Buffer.from(encrypted))
    expect(decrypted).toEqual(testBrowserBuffer)
  })
})

// NODE GENERATED KEY
describe('node-generated jwk key', () => {
  let keys: node.JwkKeyPair

  beforeAll(async () => {
    keys = await node.generateKeyPair({type: 'jwk'})
  })

  test('encrypt in browser, decrypt in node', async () => {
    const encrypted = await browser.encrypt(keys.publicKey, testBrowserBuffer)
    const decrypted = await node.decrypt(keys.privateKey, Buffer.from(encrypted))
    expect(decrypted.equals(testNodeBuffer))
  })

  test('encrypt in node, decrypt in browser', async () => {
    const encrypted = await node.encrypt(keys.publicKey, testNodeBuffer)
    const decrypted = await browser.decrypt(keys.privateKey, Buffer.from(encrypted))
    expect(decrypted).toEqual(testBrowserBuffer)
  })
})

describe('node-generated pem key', () => {
  let keys: node.PemKeyPair

  beforeAll(async () => {
    keys = await node.generateKeyPair({type: 'pem'})
  })

  test('encrypt in browser, decrypt in node', async () => {
    const encrypted = await browser.encrypt(keys.publicKey, testBrowserBuffer)
    const decrypted = await node.decrypt(keys.privateKey, Buffer.from(encrypted))
    expect(decrypted.equals(testNodeBuffer))
  })

  test('encrypt in node, decrypt in browser', async () => {
    const encrypted = await node.encrypt(keys.publicKey, testNodeBuffer)
    const decrypted = await browser.decrypt(keys.privateKey, Buffer.from(encrypted))
    expect(decrypted).toEqual(testBrowserBuffer)
  })
})

describe('node-generated mixed key', () => {
  let keys: node.KeyPair

  beforeAll(async () => {
    keys = await node.generateKeyPair()
  })

  test('encrypt in browser with jwk, decrypt in node with pem', async () => {
    const encrypted = await browser.encrypt(keys.jwk.publicKey, testBrowserBuffer)
    const decrypted = await node.decrypt(keys.pem.privateKey, Buffer.from(encrypted))
    expect(decrypted.equals(testNodeBuffer))
  })

  test('encrypt in browser with pem, decrypt in node with jwk', async () => {
    const encrypted = await browser.encrypt(keys.pem.publicKey, testBrowserBuffer)
    const decrypted = await node.decrypt(keys.jwk.privateKey, Buffer.from(encrypted))
    expect(decrypted.equals(testNodeBuffer))
  })

  test('encrypt in node with jwk, decrypt in browser with pem', async () => {
    const encrypted = await node.encrypt(keys.jwk.publicKey, testNodeBuffer)
    const decrypted = await browser.decrypt(keys.pem.privateKey, Buffer.from(encrypted))
    expect(decrypted).toEqual(testBrowserBuffer)
  })

  test('encrypt in node with pem, decrypt in browser with jwk', async () => {
    const encrypted = await node.encrypt(keys.pem.publicKey, testNodeBuffer)
    const decrypted = await browser.decrypt(keys.jwk.privateKey, Buffer.from(encrypted))
    expect(decrypted).toEqual(testBrowserBuffer)
  })
})
