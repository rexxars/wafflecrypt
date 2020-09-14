import {publicEncrypt, constants} from 'crypto'
import {Key} from '../types'
import {getKeyObject} from './keys'

export async function encrypt(key: Key, content: Buffer | string): Promise<Buffer> {
  const buffer = Buffer.isBuffer(content) ? content : Buffer.from(content)
  const encrypted = await publicEncrypt(
    {
      key: getKeyObject(key, true),
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    buffer
  )
  return encrypted
}
