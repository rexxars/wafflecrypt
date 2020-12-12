import {extractPemKey, inferType as inferPemType} from '../shared/pem'
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
  const expectedType = isPublicKey ? 'public' : 'private'
  const bucket = typeof key === 'string' ? 'pem' : 'jwk'
  const cache = keyCache[bucket][expectedType]
  if (cache.input === key && cache.output) {
    return cache.output
  }

  const type = inferType(key)
  if (type && expectedType === 'private' && expectedType !== type) {
    throw new Error(`Invalid ${expectedType} key - received a ${type} key`)
  }

  const usage: ('encrypt' | 'decrypt')[] = [isPublicKey ? 'encrypt' : 'decrypt']
  let keyObj

  try {
    if (typeof key === 'string') {
      keyObj = await window.crypto.subtle.importKey(
        type === 'public' ? 'spki' : 'pkcs8',
        base64ToArrayBuffer(extractPemKey(key)),
        algorithm,
        false,
        usage
      )
    } else {
      const keyProps =
        expectedType === 'public' && type === 'private' ? publicFromPrivate(key) : key

      keyObj = await window.crypto.subtle.importKey(
        'jwk', // Yay
        keyProps,
        algorithm,
        false,
        usage
      )
    }
  } catch (err) {
    throw new Error(`Invalid ${expectedType} key: ${err.message}`)
  }

  cache.input = key
  cache.output = keyObj
  return keyObj
}

function inferType(key: Key): 'public' | 'private' | undefined {
  if (typeof key === 'string') {
    return inferPemType(key)
  }

  if (!key.d && !key.alg) {
    return undefined
  }

  return key.d ? 'private' : 'public'
}

function publicFromPrivate(priv: Jwk) {
  const {alg, e, ext, kty, n} = priv
  return {alg, e, ext, kty, n}
}
