import { TypedArray } from '../../tdf/index.js';

import { digest, enums } from '../../nanotdf-crypto/index.js';

interface HkdfSalt {
  hkdfSalt: ArrayBuffer;
  hkdfHash: enums.HashType;
}

export default async function getHkdfSalt(buffer: TypedArray | ArrayBuffer): Promise<HkdfSalt> {
  return {
    hkdfSalt: await digest(enums.HashType.Sha256, buffer),
    hkdfHash: enums.HashType.Sha256,
  };
}
