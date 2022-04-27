import { TypedArray } from '../../tdf/index';

import { digest, enums } from '../../nanotdf-crypto/index';

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
