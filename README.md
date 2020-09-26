# wafflecrypt

Simple, opinionated (probably stupid) encryption/decryption.

Works in modern browsers that supports the [SubtleCrypto API](https://caniuse.com/mdn-api_crypto_subtle) and node.js >= 12.9.

## Details

- Uses [RSA-OAEP-256](https://tools.ietf.org/html/rfc3447) for encryption
- Can take public + private keys in the following formats
  - [JWK](https://tools.ietf.org/html/rfc7517)
  - [PEM](https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail)
    - spki for public keys
    - pkcs8 for private keys

## Installing

```sh
$ npm install wafflecrypt
```

## Usage

```js
// ESM / TypeScript
import {encrypt, decrypt} from 'wafflecrypt'

const inputData = 'encrypt-me'

const publicKey = {alg: 'RSA-OAEP-256', e: 'AQAB' /* … */} // JWK
const encrypted = await encrypt(publicKey, inputData)

const privateKey = {alg: 'RSA-OAEP-256', d: 'F9wnq…' /* */} // JWK
const outputData = await decrypt(privateKey, encrypted)

console.log(inputData === outputData)
```

## API

`Buffer` is returned for most operations in Node.js, whereas `ArrayBuffer` is used in browsers.

### Encrypt

Encrypt the given data to a Buffer/ArrayBuffer.

```ts
function encrypt(
  publicKey: JWK | PEM, // JWK as object or PEM as string
  data: Buffer | ArrayBuffer | TypedArray | string
): Promise<Buffer | ArrayBuffer>
```

### Decrypt

Decrypt the given data to a Buffer/ArrayBuffer or string (if encoding option is passed).

```ts
function decrypt(
  privateKey: JWK | PEM, // JWK as object or PEM as string
  data: Buffer | ArrayBuffer | string, // Assumes base64 if string
  options?: {encoding?: 'utf8' | 'ucs2' /* … */} // Only utf8 in browser
): Promise<Buffer | ArrayBuffer | string> // string on "encoding" option
```

### Generate key pair

Generates a keypair using random bytes, then encodes the keys as either PEM or JWK.
If no `type` is specified, it returns an object of both `jwk` and `pem` keys.

`JwkKeyPair` is an object with `publicKey` and `privateKey`, where the content is an object containing the actual JWK. Pass it to `JSON.stringify` if you want it as a string, obviously.

`PemKeyPair` is an object with `publicKey` and `privateKey`, where the content are PEM-strings.

```ts
function generateKeyPair(options?: {
  type?: 'jwk' | 'pem'
  modulusLength: number = 4096
}): Promise<JwkKeyPair | PemKeyPair | {jwk: JwkKeyPair; pem: PemKeyPair}>
```

## License

MIT © Espen Hovlandsdal
