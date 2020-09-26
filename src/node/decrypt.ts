/* eslint-disable no-redeclare */
import {privateDecrypt, constants} from 'crypto'
import {Key} from '../types'
import {getKeyObject} from './keys'

// Overloads
export async function decrypt(privateKey: Key, content: Buffer | string): Promise<Buffer>
export async function decrypt(
  privateKey: Key,
  content: Buffer | string,
  options: Omit<DecryptOptions, 'encoding'>
): Promise<Buffer>
export async function decrypt(
  privateKey: Key,
  content: Buffer | string,
  options: DecryptOptions & {encoding: BufferEncoding}
): Promise<string>

// Implementation
export async function decrypt(
  privateKey: Key,
  content: Buffer | string,
  options?: DecryptOptions
): Promise<Buffer | string> {
  const decrypted = await privateDecrypt(
    {
      key: getKeyObject(privateKey),
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    typeof content === 'string' ? Buffer.from(content, 'base64') : content
  )

  return options && options.encoding ? decrypted.toString(options.encoding) : decrypted
}

type DecryptOptions = {encoding?: BufferEncoding}

type BufferEncoding =
  | 'ascii'
  | 'utf8'
  | 'utf-8'
  | 'utf16le'
  | 'ucs2'
  | 'ucs-2'
  | 'base64'
  | 'latin1'
  | 'binary'
  | 'hex'
