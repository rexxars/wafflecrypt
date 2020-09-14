/* eslint-disable @typescript-eslint/no-explicit-any */
import asn from 'asn1.js'

export const RSAPublicKeyParams = asn.define('RSAPublicKeyParams', function (this: any) {
  this.seq().obj(this.key('n').int(), this.key('e').int())
})

export const RSAPublicKey = asn.define('RSAPublicKey', function (this: any) {
  this.seq().obj(this.key('header').use(RSAPublicKeyHeader), this.key('content').bitstr())
})

export const RSAPublicKeyHeader = asn.define('RSAPublicKeyHeader', function (this: any) {
  this.seq().obj(
    this.key('keyType').objid({
      '1.2.840.113549.1.1.1': 'RSA',
    }),
    this.null_()
  )
})

export const AlgorithmIdentifier = asn.define('AlgorithmIdentifier', function (this: any) {
  this.seq().obj(this.key('algorithm').objid(), this.key('parameters').optional().any())
})

export const PublicKeyInfo = asn.define('PublicKeyInfo', function (this: any) {
  this.seq().obj(this.key('algorithm').use(AlgorithmIdentifier), this.key('publicKey').bitstr())
})

export const Version = asn.define('Version', function (this: any) {
  this.int({
    0: 'two-prime',
    1: 'multi',
  })
})

export const OtherPrimeInfos = asn.define('OtherPrimeInfos', function (this: any) {
  this.seq().obj(this.key('ri').int(), this.key('di').int(), this.key('ti').int())
})

export const RSAPrivateKey = asn.define('RSAPrivateKey', function (this: any) {
  this.seq().obj(
    this.key('id').int(),
    this.key('n').int(),
    this.key('e').int(),
    this.key('d').int(),
    this.key('p').int(),
    this.key('q').int(),
    this.key('dp').int(),
    this.key('dq').int(),
    this.key('qi').int(),
    this.key('other').optional().use(OtherPrimeInfos)
  )
})

export const PrivateKeyInfo = asn.define('PrivateKeyInfo', function (this: any) {
  this.seq().obj(
    this.key('version').use(Version),
    this.key('algorithm').use(AlgorithmIdentifier),
    this.key('privateKey').octstr()
  )
})
