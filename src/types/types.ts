export interface Jwk {
  alg?: 'RSA-OAEP-256'
  kty: 'RSA'

  crv?: string
  d?: string
  dp?: string
  dq?: string
  e?: string
  ext?: boolean
  k?: string
  // eslint-disable-next-line camelcase
  key_ops?: string[]
  n?: string
  oth?: RsaOtherPrimesInfo[]
  p?: string
  q?: string
  qi?: string
  use?: string
  x?: string
  y?: string
}

export type Key = PemString | Jwk
export type PemString = string

interface RsaOtherPrimesInfo {
  d?: string
  r?: string
  t?: string
}
