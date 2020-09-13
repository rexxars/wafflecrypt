# wafflecrypt

Simple (probably stupid) encryption/decryption for browsers and node

## Installing

```sh
$ npm install wafflecrypt
```

## Usage

```js
// ESM / TypeScript
import {encrypt, decrypt, generateKeyPair} from 'wafflecrypt'

const inputData = 'encrypt-me'
const encrypted = await encrypt('/path/to/public-key.pem', inputData)

const outputData = await decrypt('/path/to/private-key.pem', encrypted)
console.log(inputData === outputData)
```

## License

MIT-licensed. See LICENSE.
