export interface PemKeyPair {
  publicKey: string
  privateKey: string
}

export interface JwkKeyPair {
  publicKey: Jwk
  privateKey: Jwk
}

export interface KeyPair {
  pem: PemKeyPair
  jwk: JwkKeyPair
}

export interface Jwk {
  alg?: string
  kty?: string

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
