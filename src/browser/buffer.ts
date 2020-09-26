export function stringToArrayBuffer(str: string): ArrayBuffer {
  const buf = new ArrayBuffer(str.length * 2)
  const bufView = new Uint16Array(buf)
  const strLen = str.length
  for (let i = 0; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}

export function arrayBufferToString(buffer: ArrayBuffer): string {
  return String.fromCharCode.apply(null, Array.from(new Uint8Array(buffer)))
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

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  const length = bytes.byteLength
  let binary = ''
  for (let i = 0; i < length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return window.btoa(binary)
}
