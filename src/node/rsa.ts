/* eslint-disable id-length, new-cap */

/**
 * JWK => PEM code borrowed from node-jwk (https://github.com/HyperBrain/node-jwk)
 * by Frank Schmid, licensed under Artistic-2.0 (https://opensource.org/licenses/Artistic-2.0).
 * Minor modifications to reduce lines and avoid the extra dependency.
 **/
import {Jwk} from '../types/types'
import {extractPemKey} from '../shared/pem'
import {
  PrivateKeyInfo,
  PublicKeyInfo,
  RSAPrivateKey,
  RSAPublicKey,
  RSAPublicKeyParams,
} from './asn1'

interface JwkData {
  id: number
  n: Buffer | null
  e: Buffer | null
  d: Buffer | null
  p: Buffer | null
  q: Buffer | null
  dp: Buffer | null
  dq: Buffer | null
  qi: Buffer | null
}

export function pemFromJwk(key: Jwk): {pem: string; type: 'private' | 'public'} {
  const data = getJwkData(key)
  return key.d
    ? {type: 'private', pem: RSAPrivateKey.encode(data, 'pem', {label: 'RSA PRIVATE KEY'})}
    : {type: 'public', pem: publicKeyFromJwk(data)}
}

export function jwkFromPem(pem: string): Jwk {
  const head = pem.slice(0, pem.indexOf('\n')).trim()
  const decoder = getDecoder(head)
  const body = extractPemKey(pem).replace(/[^\w\d+/=]+/g, '')
  return decoder(Buffer.from(body, 'base64'))
}

const zeroBuffer = Buffer.alloc(1, 0)

function unsigned(bignum: Buffer | null): Buffer | null {
  if (bignum === null || !Buffer.isBuffer(bignum)) {
    return bignum
  }

  if (bignum.readInt8(0) < 0) {
    return Buffer.concat([zeroBuffer, bignum], bignum.length + 1)
  }

  return bignum
}

function publicKeyFromJwk(data: JwkData): string {
  const keyParams = RSAPublicKeyParams.encode(data, 'der')
  const params = {
    header: {keyType: 'RSA'},
    content: {data: keyParams},
  }

  return RSAPublicKey.encode(params, 'pem', {label: 'PUBLIC KEY'})
}

function getJwkData(key: Jwk): JwkData {
  const n = key.n ? Buffer.from(key.n, 'base64') : null
  const e = key.e ? Buffer.from(key.e, 'base64') : null
  const d = key.d ? Buffer.from(key.d, 'base64') : null
  const p = key.p ? Buffer.from(key.p, 'base64') : null
  const q = key.q ? Buffer.from(key.q, 'base64') : null
  const dp = key.dp ? Buffer.from(key.dp, 'base64') : null
  const dq = key.dq ? Buffer.from(key.dq, 'base64') : null
  const qi = key.qi ? Buffer.from(key.qi, 'base64') : null

  return {
    id: 0,
    n: unsigned(n),
    e: unsigned(e),
    d: unsigned(d),
    p: unsigned(p),
    q: unsigned(q),
    dp: unsigned(dp),
    dq: unsigned(dq),
    qi: unsigned(qi),
  }
}

function decodeRsaPublic(buffer: Buffer): Jwk {
  const key = RSAPublicKeyParams.decode(buffer, 'der')
  const e = pad(key.e.toString(16))
  return {
    kty: 'RSA',
    n: bn2base64url(key.n),
    e: hex2b64url(e),
  }
}

function decodeRsaPrivate(buffer: Buffer): Jwk {
  const key = RSAPrivateKey.decode(buffer, 'der')
  const e = pad(key.e.toString(16))
  return {
    kty: 'RSA',
    n: bn2base64url(key.n),
    e: hex2b64url(e),
    d: bn2base64url(key.d),
    p: bn2base64url(key.p),
    q: bn2base64url(key.q),
    dp: bn2base64url(key.dp),
    dq: bn2base64url(key.dq),
    qi: bn2base64url(key.qi),
  }
}

function decodePublic(buffer: Buffer): Jwk {
  const info = PublicKeyInfo.decode(buffer, 'der')
  return decodeRsaPublic(info.publicKey.data)
}

function decodePrivate(buffer: Buffer): Jwk {
  const info = PrivateKeyInfo.decode(buffer, 'der')
  return decodeRsaPrivate(info.privateKey)
}

function bn2base64url(bn: number): string {
  return hex2b64url(pad(bn.toString(16)))
}

function pad(hex: string): string {
  return hex.length % 2 === 1 ? `0${hex}` : hex
}

function urlize(base64: string): string {
  // eslint-disable-next-line no-div-regex
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

function hex2b64url(str: string): string {
  return urlize(Buffer.from(str, 'hex').toString('base64'))
}

function getDecoder(header: string): (buffer: Buffer) => Jwk {
  const match = /^-----BEGIN (RSA )?(PUBLIC|PRIVATE) KEY-----$/.exec(header)
  if (!match) {
    throw new Error('Unrecognized PEM key type')
  }

  const isRSA = Boolean(match[1])
  const isPrivate = match[2] === 'PRIVATE'
  if (isPrivate) {
    return isRSA ? decodeRsaPrivate : decodePrivate
  }

  return isRSA ? decodeRsaPublic : decodePublic
}
