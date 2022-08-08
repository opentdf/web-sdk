export default function getCryptoLib(): SubtleCrypto {
  if (typeof window !== 'undefined') {
    let crypto = window.crypto;
    if (!crypto && window.msCrypto) {
      crypto = window.msCrypto;
    }
    let subtleCrypto = crypto.subtle;
    if (!subtleCrypto && crypto.webkitSubtle) {
      subtleCrypto = crypto.webkitSubtle;
    }
    return subtleCrypto;
  }

  return globalThis.crypto.webcrypto.subtle;
}
