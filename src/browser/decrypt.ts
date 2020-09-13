import {Key} from '../types'
import {getKeyObject} from './keys'
import {stringToArrayBuffer} from './buffer'

export async function decrypt(
  privateKey: Key,
  content: string | ArrayBuffer
): Promise<ArrayBuffer> {
  const data = typeof content === 'string' ? stringToArrayBuffer(content) : content
  const key = await getKeyObject(privateKey)
  const buf = await window.crypto.subtle.decrypt({name: 'RSA-OAEP'}, key, data)
  return buf
}
