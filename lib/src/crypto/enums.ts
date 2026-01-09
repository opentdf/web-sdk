export enum AlgorithmName {
  ECDH = 'ECDH',
  ECDSA = 'ECDSA',
  ES256 = 'ES256',
  HKDF = 'HKDF',
  RSA_OAEP = 'RSA-OAEP',
  RSA_PSS = 'RSA-PSS',
}

export enum NamedCurve {
  P256 = 'P-256',
  P384 = 'P-384',
  P512 = 'P-512',
}

export enum CipherType {
  AesGcm = 'AES-GCM',
}

export enum HashType {
  Sha1 = 'SHA-1',
  Sha256 = 'SHA-256',
  Sha384 = 'SHA-384',
  Sha512 = 'SHA-512',
}

export enum KeyFormat {
  Raw = 'raw',
  Pkcs8 = 'pkcs8',
  Spki = 'spki',
}

export enum KeyType {
  Private = 'private',
  Public = 'public',
}

export enum KeyUsageType {
  Encrypt = 'encrypt',
  Decrypt = 'decrypt',
  DeriveBits = 'deriveBits',
  DeriveKey = 'deriveKey',
  Verify = 'verify',
  Sign = 'sign',
  UnwrapKey = 'unwrapKey',
  WrapKey = 'wrapKey',
}
