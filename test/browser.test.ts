import {encrypt, decrypt} from '../src/browser'
import {stringToArrayBuffer} from '../src/browser/buffer'
import {privateKeyJwk, privateKeyPem, publicKeyJwk, publicKeyPem} from './fixtures'

const testString = 'Sample input data!'
const testBuffer = stringToArrayBuffer(testString)

test('encrypt/decrypt (pem string)', async () => {
  const encrypted = await encrypt(publicKeyPem, testBuffer)
  const decrypted = await decrypt(privateKeyPem, encrypted)
  expect(decrypted).toEqual(testBuffer)
})

test('encrypt/decrypt (jwk object)', async () => {
  const encrypted = await encrypt(publicKeyJwk, testBuffer)
  const decrypted = await decrypt(privateKeyJwk, encrypted)
  expect(decrypted).toEqual(testBuffer)
})
