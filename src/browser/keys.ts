import {Jwk, Key} from '../types'
import {base64ToArrayBuffer} from './buffer'

interface TypedKeyCache<T> {
  private: {input?: T; output?: CryptoKey}
  public: {input?: T; output?: CryptoKey}
}

interface KeyCache {
  jwk: TypedKeyCache<Jwk>
  pem: TypedKeyCache<string>
}

const keyCache: KeyCache = {
  jwk: {private: {}, public: {}},
  pem: {private: {}, public: {}},
}

const algorithm = {name: 'RSA-OAEP', hash: 'SHA-256'}

export async function getKeyObject(key: Key, isPublicKey = false): Promise<CryptoKey> {
  const type = isPublicKey ? 'public' : 'private'
  const bucket = typeof key === 'string' ? 'pem' : 'jwk'
  const cache = keyCache[bucket][type]
  if (cache.input === key && cache.output) {
    return cache.output
  }

  const usage: ('encrypt' | 'decrypt')[] = [isPublicKey ? 'encrypt' : 'decrypt']
  let keyObj
  if (typeof key === 'string') {
    keyObj = await window.crypto.subtle.importKey(
      isPublicKey ? 'spki' : 'pkcs8',
      extractPemKey(key),
      algorithm,
      false,
      usage
    )
  } else {
    keyObj = await window.crypto.subtle.importKey(
      'jwk', // Yay
      key,
      algorithm,
      false,
      usage
    )
  }

  cache.input = key
  cache.output = keyObj
  return keyObj
}

function extractPemKey(pem: string) {
  const lines = pem
    .toString()
    .split(/(\r\n|\r|\n)+/g)
    .filter((line) => line.trim().length !== 0)

  const body = lines.slice(1, -1).join('')
  const base64 = body.replace(/[^\w\d+/=]+/g, '')
  return base64ToArrayBuffer(base64)
}
