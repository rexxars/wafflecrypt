/* eslint-disable no-redeclare */
import {JwkKeyPair, KeyPair, PemKeyPair} from '../types'
import {arrayBufferToString} from './buffer'

interface Options {
  type?: 'jwk' | 'pem'
  modulusLength?: number
}

export async function generateKeyPair(options?: Omit<Options, 'type'>): Promise<KeyPair>
export async function generateKeyPair(options?: Options & {type: 'pem'}): Promise<PemKeyPair>
export async function generateKeyPair(options?: Options & {type: 'jwk'}): Promise<JwkKeyPair>
export async function generateKeyPair({type, modulusLength = 4096}: Options = {}): Promise<
  JwkKeyPair | PemKeyPair | KeyPair
> {
  const subtle = window.crypto.subtle
  const keyPair = await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: {name: 'SHA-256'},
    },
    true,
    ['encrypt', 'decrypt']
  )

  const jwk = (!type || type === 'jwk') && {
    publicKey: await subtle.exportKey('jwk', keyPair.publicKey),
    privateKey: await subtle.exportKey('jwk', keyPair.privateKey),
  }

  const pem = (!type || type === 'pem') && {
    publicKey: wrap(await subtle.exportKey('spki', keyPair.publicKey), 'PUBLIC'),
    privateKey: wrap(await subtle.exportKey('pkcs8', keyPair.privateKey), 'PRIVATE'),
  }

  if (type === 'jwk' && jwk) {
    return jwk
  }

  if (type === 'pem' && pem) {
    return pem
  }

  return {jwk: jwk as JwkKeyPair, pem: pem as PemKeyPair}
}

function wrap(key: ArrayBuffer, type: 'PUBLIC' | 'PRIVATE'): string {
  return [
    `-----BEGIN ${type} KEY-----`,
    cap(btoa(arrayBufferToString(key))),
    `-----END ${type} KEY-----`,
  ].join('\n')
}

function cap(pem: string): string {
  const numLines = Math.ceil(pem.length / 64)
  const lines = new Array(numLines)
  for (let i = 0; i < numLines; i++) {
    lines[i] = pem.slice(i * 64, (i + 1) * 64)
  }
  return lines.join('\n')
}
