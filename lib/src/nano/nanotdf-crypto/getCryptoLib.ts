export default function getCryptoLib(): SubtleCrypto {
  if (typeof window !== 'undefined') {
    let crypto = window.crypto;
    if (!crypto) {
      // @ts-ignore: Swap in incompatible crypto lib
      crypto = window.msCrypto;
    }
    let subtleCrypto = crypto.subtle;
    if (!subtleCrypto) {
      // @ts-ignore: Swap in incompatible crypto lib
      subtleCrypto = crypto.webkitSubtle;
    }
    return subtleCrypto;
  }

  // @ts-ignore
  return globalThis.crypto.webcrypto.subtle;
}
