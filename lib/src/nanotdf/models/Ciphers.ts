import CipherEnum from '../enum/CipherEnum.js';
import InvalidCipherError from '../errors/InvalidCipherError.js';

interface CipherInterface {
  name: CipherEnum;
  length: number;
}

export const Aes256Gcm64: CipherInterface = {
  name: CipherEnum.AES_256_GCM_64,
  length: 64,
};

export const Aes256Gcm96: CipherInterface = {
  name: CipherEnum.AES_256_GCM_96,
  length: 96,
};

export const Aes256Gcm104: CipherInterface = {
  name: CipherEnum.AES_256_GCM_104,
  length: 104,
};

export const Aes256Gcm112: CipherInterface = {
  name: CipherEnum.AES_256_GCM_112,
  length: 112,
};

export const Aes256Gcm120: CipherInterface = {
  name: CipherEnum.AES_256_GCM_120,
  length: 120,
};

export const Aes256Gcm128: CipherInterface = {
  name: CipherEnum.AES_256_GCM_128,
  length: 128,
};

export function getBitLength(cipher: CipherEnum): number {
  switch (cipher) {
    case CipherEnum.AES_256_GCM_64:
      return Aes256Gcm64.length;
    case CipherEnum.AES_256_GCM_96:
      return Aes256Gcm96.length;
    case CipherEnum.AES_256_GCM_104:
      return Aes256Gcm104.length;
    case CipherEnum.AES_256_GCM_112:
      return Aes256Gcm112.length;
    case CipherEnum.AES_256_GCM_120:
      return Aes256Gcm120.length;
    case CipherEnum.AES_256_GCM_128:
      return Aes256Gcm128.length;
    default:
      throw new InvalidCipherError();
  }
}

// export default {
//   Aes256Gcm64,
//   Aes256Gcm96,
//   Aes256Gcm104,
//   Aes256Gcm112,
//   Aes256Gcm120,
//   Aes256Gcm128,

//   getBitLength,
// };
