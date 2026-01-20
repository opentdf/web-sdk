export enum Ciphers {
  AesGcm = 'AES-GCM',
}

export enum CipherTagLengths {
  AesGcm = 128,
}

const cipherKeys = [];
for (const cipherKey in Ciphers) {
  cipherKeys.push(cipherKey);
}
export const supportedCiphers = cipherKeys;
