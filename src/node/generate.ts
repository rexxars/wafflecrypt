/* eslint-disable no-redeclare */
import {promisify} from 'util'
import {generateKeyPair as generateKey} from 'crypto'
import {JwkKeyPair, KeyPair, PemKeyPair} from '../types'
import {jwkFromPem} from './rsa'

const generate = promisify(generateKey)

interface Options {
  type?: 'pem' | 'jwk'
  modulusLength?: number
}

export async function generateKeyPair(options?: Omit<Options, 'type'>): Promise<KeyPair>
export async function generateKeyPair(options?: Options & {type: 'pem'}): Promise<PemKeyPair>
export async function generateKeyPair(options?: Options & {type: 'jwk'}): Promise<JwkKeyPair>
export async function generateKeyPair({type, modulusLength = 4096}: Options = {}): Promise<
  JwkKeyPair | PemKeyPair | KeyPair
> {
  const {publicKey, privateKey} = await generate('rsa', {modulusLength})
  const pem = {
    publicKey: publicKey.export({type: 'spki', format: 'pem'}).toString(),
    privateKey: privateKey.export({type: 'pkcs8', format: 'pem'}).toString(),
  }

  const jwk = {
    publicKey: jwkFromPem(pem.publicKey),
    privateKey: jwkFromPem(pem.privateKey),
  }

  if (type) {
    return type === 'jwk' ? jwk : pem
  }

  return {jwk, pem}
}
