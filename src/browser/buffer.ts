export function stringToArrayBuffer(str: string): ArrayBuffer {
  const buf = new ArrayBuffer(str.length * 2)
  const bufView = new Uint16Array(buf)
  const strLen = str.length
  for (let i = 0; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64)
  const len = binary.length
  const bytes = new Uint8Array(len)
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}
