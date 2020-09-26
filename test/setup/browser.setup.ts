import {TextDecoder, TextEncoder} from 'util'
import {Crypto} from '@peculiar/webcrypto'

global.crypto = new Crypto()
global.TextDecoder = TextDecoder
global.TextEncoder = TextEncoder
