import {join} from 'path'
import {readFileSync} from 'fs'

const privateKeyPemPath = join(__dirname, 'privateKey.pem')
const publicKeyPemPath = join(__dirname, 'publicKey.pem')
const privateKeyJwkPath = join(__dirname, 'privateKey.json')
const publicKeyJwkPath = join(__dirname, 'publicKey.json')

export const privateKeyPem = readFileSync(privateKeyPemPath, 'utf8')
export const publicKeyPem = readFileSync(publicKeyPemPath, 'utf8')

export const privateKeyJwk = JSON.parse(readFileSync(privateKeyJwkPath, 'utf8'))
export const publicKeyJwk = JSON.parse(readFileSync(publicKeyJwkPath, 'utf8'))
