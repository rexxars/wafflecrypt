/* eslint-disable no-redeclare */
import {Key} from '../types'
import {getKeyObject} from './keys'
import {base64ToArrayBuffer} from './buffer'

const textDecoder = new TextDecoder()

// Overloads
export async function decrypt(privateKey: Key, content: ArrayBuffer | string): Promise<Buffer>
export async function decrypt(
  privateKey: Key,
  content: Buffer | string,
  options: Omit<DecryptOptions, 'encoding'>
): Promise<ArrayBuffer>
export async function decrypt(
  privateKey: Key,
  content: Buffer | string,
  options: DecryptOptions & {encoding: BufferEncoding}
): Promise<string>

// Implementation
export async function decrypt(
  privateKey: Key,
  content: ArrayBuffer | string,
  options?: DecryptOptions
): Promise<ArrayBuffer | string> {
  const data = typeof content === 'string' ? base64ToArrayBuffer(content) : content
  const key = await getKeyObject(privateKey)
  const buf = await window.crypto.subtle.decrypt({name: 'RSA-OAEP'}, key, data)
  return options && options.encoding ? textDecoder.decode(buf) : buf
}

type DecryptOptions = {encoding?: BufferEncoding}
type BufferEncoding = 'utf8' | 'utf-8'
