/* eslint @typescript-eslint/ban-ts-comment: "off" */

import crypto from "crypto";

export default function getCryptoLib(): any {
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
  // if (typeof globalThis !== 'undefined') {
  //   // @ts-ignore: Swap in incompatible crypto lib
  //   return globalThis.crypto.subtle;
  // }
  console.log('crypto lib: ', crypto);
  // @ts-ignore: Giving up
  return crypto.webcrypto.subtle;
}
