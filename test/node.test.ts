import {encrypt, decrypt} from '../src/node'
import {privateKeyJwk, privateKeyPem, publicKeyJwk, publicKeyPem} from './fixtures'

const testBuffer = Buffer.from('Sample input data!')

test('encrypt/decrypt (pem string)', async () => {
  const encrypted = await encrypt(publicKeyPem, testBuffer)
  const decrypted = await decrypt(privateKeyPem, encrypted)
  expect(decrypted.equals(testBuffer))
})

test('encrypt/decrypt (jwk object)', async () => {
  const encrypted = await encrypt(publicKeyJwk, testBuffer)
  const decrypted = await decrypt(privateKeyJwk, encrypted)
  expect(decrypted.equals(testBuffer))
})
