import {extractPemKey} from '../shared/pem'
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
      base64ToArrayBuffer(extractPemKey(key)),
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
