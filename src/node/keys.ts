import {createPrivateKey, createPublicKey, KeyObject} from 'crypto'
import {inferType} from '../shared/pem'
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
  const expectedType = isPublicKey ? 'public' : 'private'
  const bucket = typeof key === 'string' ? 'pem' : 'jwk'
  const cache = keyCache[bucket][expectedType]
  if (cache.input === key && cache.output) {
    return cache.output
  }

  const {pem, type} =
    typeof key === 'string' ? {pem: key, type: inferType(key)} : pemFromJwk(key, expectedType)

  if (type && expectedType !== type) {
    throw new Error(`Invalid ${expectedType} key - received a ${type} key`)
  }

  try {
    const keyObj = isPublicKey ? createPublicKey(pem) : createPrivateKey(pem)

    cache.input = key
    cache.output = keyObj

    return keyObj
  } catch (err) {
    throw new Error(`Invalid ${expectedType} key: ${err.message}`)
  }
}
