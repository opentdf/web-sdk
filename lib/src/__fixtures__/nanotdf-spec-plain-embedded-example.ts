/**
 * This comes from the nanoTDF spec basic example and uses the following parameters:
 *
 * It following urls for a kas and policy
 *   - KAS URL: https://etheria.local/kas
 *   - Policy : {"body":{"dataAttributes":[],"dissem":["Charlie_1234","bob_5678"]},"uuid":"e95c2e50-c465-48a5-a167-ef98d2ccf67a"}
 * ECC Mode
 *   - `use_ecdsa_binding` is `True`
 *   - ECC Params is `0x00` (for `secp256r1`)
 * Symmetric and Payload Config
 *   - `has_signature` is `True`
 *   - Mode is `0x00` for `AES256GCM` with a 64-bit tag
 * Payload
 *   - The plaintext payload is `Virtru`.
 *
 * NOTE This uses the deprecated 3 byte iv.
 */

import PolicyTypeEnum from '../nanotdf/enum/PolicyTypeEnum.js';
import hexArrayTag from '../../test/nanotdf/helpers/hexArrayTag.js';

// 6.1.5 nanotdf
export const nanotdf = `
TDFMARFldGhlcmlhLmxvY2FsL2thc4AAAQBxeyJib2R5Ijp7ImRhdGFBdHRyaWJ1dGVzIjpbXSwiZGlz
c2VtIjpbIkNoYXJsaWVfMTIzNCIsImJvYl81Njc4Il19LCJ1dWlkIjoiZTk1YzJlNTAtYzQ2NS00OGE1
LWExNjctZWY5OGQyY2NmNjdhIn2avSz7nTV08u+z0lNoOax2ZSWlNtycmvQLS4zHNJn/2i8E1p+KGUx+
3ld0YkJETK7FIztiXbh5ChaU8qgVm7jHA0H20+g4w6gHywRmOGHxK5s6b/oqoFIbc9pMHc/GI2IvAAAR
eO9leyauC42VKckiAm5GJxs=
`;

export const header = {
  magicNumberVersion: hexArrayTag`4c 31 4c`, // L1L
  kas: {
    protocol: 0x01, // Https
    length: 17, // length of "etheria.local/kas"
    body: 'etheria.local/kas',
  },
  eccBindingMode: {
    useECDSABinding: true,
    ephemeralCurveName: 0x00, // SECP256R1
  },
  symmetricPayloadConfig: {
    hasSignature: false,
    signatureCurveName: 0x00, // SECP256R1
    symmetricCipher: 0x00, // AES_256_GCM_64
  },
  policy: {
    type: PolicyTypeEnum.EmbeddedText,
    content: hexArrayTag`
      7b 22 62 6f 64 79 22 3a 7b 22 64 61 74 61 41 74 74 72 69 62
      75 74 65 73 22 3a 5b 5d 2c 22 64 69 73 73 65 6d 22 3a 5b 22
      43 68 61 72 6c 69 65 5f 31 32 33 34 22 2c 22 62 6f 62 5f 35
      36 37 38 22 5d 7d 2c 22 75 75 69 64 22 3a 22 65 39 35 63 32
      65 35 30 2d 63 34 36 35 2d 34 38 61 35 2d 61 31 36 37 2d 65
      66 39 38 64 32 63 63 66 36 37 61 22 7d
    `,

    binding: hexArrayTag`
      9a bd 2c fb 9d 35 74 f2 ef b3 d2 53 68 39 ac 76 65 25 a5 36
      dc 9c 9a f4 0b 4b 8c c7 34 99 ff da 2f 04 d6 9f 8a 19 4c 7e
      de 57 74 62 42 44 4c ae c5 23 3b 62 5d b8 79 0a 16 94 f2 a8
      15 9b b8 c7
    `,
  },
  ephemeralPublicKey: hexArrayTag`
    03 41 f6 d3 e8 38 c3 a8 07 cb 04 66 38 61 f1 2b 9b 3a 6f fa
    2a a0 52 1b 73 da 4c 1d cf c6 23 62 2f
  `,
};

export const payload = {
  iv: hexArrayTag`78 ef 65`,
  ciphertext: hexArrayTag`7b 26 ae 0b 8d 95`,
  authTag: hexArrayTag`29 c9 22 02 6e 46 27 1b`,
};

export const signature = {
  publicKey: hexArrayTag``,
  signature: hexArrayTag``,
};
