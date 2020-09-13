# wafflecrypt

Simple, opinionated (probably stupid) encryption/decryption.

Works in modern browsers (that supports WebCrypto) and node.js (>= 12.9).

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

## License

MIT-licensed. See LICENSE.
