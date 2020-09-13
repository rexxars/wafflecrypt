/* eslint-disable id-length */

/**
 * JWK => PEM code borrowed from node-jwk (https://github.com/HyperBrain/node-jwk)
 * by Frank Schmid, licensed under Artistic-2.0 (https://opensource.org/licenses/Artistic-2.0).
 * Minor modifications to reduce lines and avoid the extra dependency.
 **/
import asn from 'asn1.js'
import {Jwk} from 'types/types'

export function pemFromJwk(key: Jwk): string {
  const data = getJwkData(key)
  return key.d
    ? RSAPrivateKey.encode(data, 'pem', {label: 'RSA PRIVATE KEY'})
    : publicKeyFromJwk(data)
}

const zeroBuffer = Buffer.alloc(1, 0)

function unsigned(bignum: Buffer | null) {
  if (bignum === null || !Buffer.isBuffer(bignum)) {
    return bignum
  }

  if (bignum.readInt8(0) < 0) {
    return Buffer.concat([zeroBuffer, bignum], bignum.length + 1)
  }

  return bignum
}

const RSAPrivateKey = asn.define('RSAPrivateKey', function (this: any) {
  this.seq().obj(
    this.key('id').int(),
    this.key('n').int(),
    this.key('e').int(),
    this.key('d').int(),
    this.key('p').int(),
    this.key('q').int(),
    this.key('dp').int(),
    this.key('dq').int(),
    this.key('qi').int()
  )
})

const RSAPublicKeyHeader = asn.define('RSAPublicKeyHeader', function (this: any) {
  this.seq().obj(
    this.key('keyType').objid({
      '1.2.840.113549.1.1.1': 'RSA',
    }),
    this.null_()
  )
})

const RSAPublicKeyParams = asn.define('RSAPublicKeyParams', function (this: any) {
  this.seq().obj(this.key('n').int(), this.key('e').int())
})

const RSAPublicKey = asn.define('RSAPublicKey', function (this: any) {
  this.seq().obj(this.key('header').use(RSAPublicKeyHeader), this.key('content').bitstr())
})

function publicKeyFromJwk(data: any): string {
  const keyParams = RSAPublicKeyParams.encode(data, 'der')

  const params = {
    header: {
      keyType: 'RSA',
    },
    content: {
      data: keyParams,
    },
  }

  return RSAPublicKey.encode(params, 'pem', {label: 'PUBLIC KEY'})
}

function getJwkData(key: Jwk) {
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
