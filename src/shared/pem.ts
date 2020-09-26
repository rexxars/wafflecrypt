export function extractPemKey(pem: string): string {
  let lines = pem.trim().split(/(\r\n|\r|\n)+/g)
  const end = lines.length - 1
  const head = lines[0].match(/-----BEGIN (.*)-----/)
  const foot = lines[end].match(/-----END (.*)-----/)

  if (head) {
    lines = lines.slice(1, end)
    if (!foot || head[1] !== foot[1]) {
      throw new Error('Headers and footers do not match')
    }
  }

  return lines.join('').replace(/[^\w\d+/=]+/g, '')
}

export function inferType(pem: string): 'public' | 'private' | undefined {
  const [, type] = pem.match(/---BEGIN .*?(PUBLIC|PRIVATE)/) || []
  return type ? (type.toLowerCase() as 'public' | 'private') : undefined
}
