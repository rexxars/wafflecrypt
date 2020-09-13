import {createPrivateKey, createPublicKey, KeyObject} from 'crypto'
import {Jwk, Key} from '../types'
import {pemFromJwk} from './rsa'

interface TypedKeyCache<T> {
  private: {input?: T; output?: KeyObject}
  public: {input?: T; output?: KeyObject}
}

interface KeyCache {
  jwk: TypedKeyCache<Jwk>
  pem: TypedKeyCache<string>
}

const keyCache: KeyCache = {
  jwk: {private: {}, public: {}},
  pem: {private: {}, public: {}},
}

export function getKeyObject(key: Key, isPublicKey = false): KeyObject {
  const type = isPublicKey ? 'public' : 'private'
  const bucket = typeof key === 'string' ? 'pem' : 'jwk'
  const cache = keyCache[bucket][type]
  if (cache.input === key && cache.output) {
    return cache.output
  }

  const pemKey = typeof key === 'string' ? key : pemFromJwk(key)
  const keyObj = isPublicKey ? createPublicKey(pemKey) : createPrivateKey(pemKey)

  cache.input = key
  cache.output = keyObj

  return keyObj
}
