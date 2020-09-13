import {Key} from '../types'
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

export async function encrypt(key: Key, content: EncryptableInput): Promise<ArrayBuffer> {
  const data = typeof content === 'string' ? new TextEncoder().encode(content) : content
  const keyObj = await getKeyObject(key, true)
  const buf = await window.crypto.subtle.encrypt({name: 'RSA-OAEP'}, keyObj, data)
  return buf
}
