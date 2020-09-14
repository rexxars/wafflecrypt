import {promisify} from 'util'
import {generateKeyPair as generateKey} from 'crypto'
import {JwkKeyPair, PemKeyPair} from '../types'
import {jwkFromPem} from './rsa'

const generate = promisify(generateKey)

interface Options {
  type?: 'jwk' | 'pem'
  modulusLength?: number
}

export async function generateKeyPair({type = 'jwk', modulusLength = 4096}: Options = {}): Promise<
  JwkKeyPair | PemKeyPair
> {
  const {publicKey, privateKey} = await generate('rsa', {modulusLength})
  const pem = {
    publicKey: publicKey.export({type: 'spki', format: 'pem'}).toString(),
    privateKey: privateKey.export({type: 'pkcs8', format: 'pem'}).toString(),
  }

  if (type === 'pem') {
    return pem
  }

  return {
    publicKey: jwkFromPem(pem.publicKey),
    privateKey: jwkFromPem(pem.privateKey),
  }
}
