/**
 * This comes from the nanoTDF spec basic example and uses the following parameters:
 *
 * It following urls for a kas and policy
 *   - KAS URL: https://kas.virtru.com
 *   - Policy URL: https://kas.virtru.com/policy
 * ECC Mode
 *   - `use_ecdsa_binding` is `True`
 *   - ECC Params is `0x00` (for `secp256r1`)
 * Symmetric and Payload Config
 *   - `has_signature` is `True`
 *   - Mode is `0x00` for `AES256GCM` with a 64-bit tag
 * Payload
 *   - The plaintext payload is `DON'T`.
 *
 * NOTE This uses the deprecated 3 byte iv.
 * @link https://github.com/virtru/nanotdf/blob/master/spec/index.md#61-basic-example
 */

import PolicyTypeEnum from '../nanotdf/enum/PolicyTypeEnum.js';
import hexArrayTag from '../../test/nanotdf/helpers/hexArrayTag.js';

// 6.1.5 nanotdf
export const nanotdf = `
TDFMAQ9rYXMuZXRlcm5vcy54eXqAAAIAYF8U50nNasAtfjke5lGt43Xih+LDfGkfdhFazlOj+Emsn7drDxz7e+ALYcpX/jVYFBz/
aafjBjLnhlprwcDptENx8ODEjfpeygQ1bWC8UdAlHrZmcXMppqKeioUSCQK5hBA/dswcZggy4LB8r5EfwVBtlVf5RDdUp3fU7+Bv
GtnSAeLvGsARKzdyTF9PpArXAc9AbC7VnbVyA7OMpPF0YFQDQHcAwtHIyzVZNSzarQdcChszFMezBVRfN4XaSZ6Q/eAAABAedI5H
3egvvoM+IgjYoK1C
`;

export const header = {
  magicNumberVersion: hexArrayTag`4c 31 4c`, // L1L
  kas: {
    protocol: 0x01, // Https
    length: 15, // length of "kas.virtru.com"
    body: 'kas.eternos.xyz',
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
    type: PolicyTypeEnum.EmbeddedEncrypted,
    content: hexArrayTag`
      5F 14 E7 49 CD 6A C0 2D 7E 39 1E E6 51 AD E3 75 E2 87 E2 C3
      7C 69 1F 76 11 5A CE 53 A3 F8 49 AC 9F B7 6B 0F 1C FB 7B E0
      0B 61 CA 57 FE 35 58 14 1C FF 69 A7 E3 06 32 E7 86 5A 6B C1
      C0 E9 B4 43 71 F0 E0 C4 8D FA 5E CA 04 35 6D 60 BC 51 D0 25
      1E B6 66 71 73 29 A6 A2 9E 8A 85 12 09 02 B9 84
    `,
    binding: hexArrayTag`
      10 3F 76 CC 1C 66 08 32 E0 B0 7C AF 91 1F C1 50 6D 95 57 F9
      44 37 54 A7 77 D4 EF E0 6F 1A D9 D2 01 E2 EF 1A C0 11 2B 37
      72 4C 5F 4F A4 0A D7 01 CF 40 6C 2E D5 9D B5 72 03 B3 8C A4
      F1 74 60 54
    `,
  },
  ephemeralPublicKey: hexArrayTag`
    03 40 77 00 C2 D1 C8 CB 35 59 35 2C DA AD 07 5C 0A 1B 33 14
    C7 B3 05 54 5F 37 85 DA 49 9E 90 FD E0
  `,
};

export const payload = {
  iv: hexArrayTag`1E 74 8E`,
  ciphertext: hexArrayTag`47 DD E8 2F BE`,
  authTag: hexArrayTag`83 3E 22 08 D8 A0 AD 42`,
};

export const signature = {
  publicKey: hexArrayTag``,
  signature: hexArrayTag``,
};
