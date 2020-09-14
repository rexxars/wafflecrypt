import {encrypt, decrypt, generateKeyPair} from '../src/node'
import {privateKeyJwk, privateKeyPem, publicKeyJwk, publicKeyPem} from './fixtures'

const testString = 'Sample input data!'
const testBuffer = Buffer.from(testString)

test('encrypt/decrypt (jwk object)', async () => {
  const encrypted = await encrypt(publicKeyJwk, testBuffer)
  const decrypted = await decrypt(privateKeyJwk, encrypted)
  expect(decrypted.equals(testBuffer))
})

test('encrypt/decrypt (pem string)', async () => {
  const encrypted = await encrypt(publicKeyPem, testBuffer)
  const decrypted = await decrypt(privateKeyPem, encrypted)
  expect(decrypted.equals(testBuffer))
})

test('generate keypair (jwk)', async () => {
  const pair = await generateKeyPair({type: 'jwk'})
  expect(pair.privateKey).toHaveProperty('kty', 'RSA')
  expect(pair.publicKey).toHaveProperty('kty', 'RSA')

  const encrypted = await encrypt(pair.publicKey, testString)
  const decrypted = await decrypt(pair.privateKey, encrypted)
  expect(decrypted.equals(testBuffer))
})

test('generate keypair (pem)', async () => {
  const pair = await generateKeyPair({type: 'pem'})
  expect(pair.privateKey).toMatch(/-----BEGIN PRIVATE KEY-----/)
  expect(pair.publicKey).toMatch(/-----BEGIN PUBLIC KEY-----/)

  const encrypted = await encrypt(pair.publicKey, testString)
  const decrypted = await decrypt(pair.privateKey, encrypted)
  expect(decrypted.equals(testBuffer))
})
