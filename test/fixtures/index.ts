import {join} from 'path'
import {readFileSync} from 'fs'
import {Jwk} from '../../src/node'

const privateKeyPemPath = join(__dirname, 'privateKey.pem')
const publicKeyPemPath = join(__dirname, 'publicKey.pem')
const privateKeyJwkPath = join(__dirname, 'privateKey.json')
const publicKeyJwkPath = join(__dirname, 'publicKey.json')

export const privateKeyPem = readFileSync(privateKeyPemPath, 'utf8')
export const publicKeyPem = readFileSync(publicKeyPemPath, 'utf8')

export const privateKeyJwk: Jwk = JSON.parse(readFileSync(privateKeyJwkPath, 'utf8'))
export const publicKeyJwk: Jwk = JSON.parse(readFileSync(publicKeyJwkPath, 'utf8'))
