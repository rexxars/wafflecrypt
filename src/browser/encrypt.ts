import {Key} from '../types'
import {stringToArrayBuffer} from './buffer'
import {getKeyObject} from './keys'

export type EncryptableInput =
  | string
  | Buffer
  | Int8Array
  | Int16Array
  | Int32Array
  | Uint8Array
  | Uint16Array
  | Uint32Array
  | Uint8ClampedArray
  | Float32Array
  | Float64Array
  | DataView
  | ArrayBuffer

export async function encrypt(publicKey: Key, content: EncryptableInput): Promise<ArrayBuffer> {
  const data = typeof content === 'string' ? stringToArrayBuffer(content) : content
  const keyObj = await getKeyObject(publicKey, true)
  const buf = await window.crypto.subtle.encrypt({name: 'RSA-OAEP'}, keyObj, data)
  return buf
}
