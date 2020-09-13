import {privateDecrypt, constants} from 'crypto'
import {Key} from '../types'
import {getKeyObject} from './keys'

export async function decrypt(privateKey: Key, content: Buffer): Promise<Buffer> {
  const decrypted = await privateDecrypt(
    {
      key: getKeyObject(privateKey),
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    content
  )
  return decrypted
}
