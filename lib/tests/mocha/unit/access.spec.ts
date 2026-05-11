import { expect } from 'chai';

import { isPublicKeyAlgorithm, type KasPublicKeyAlgorithm } from '../../../src/access.js';

describe('access', () => {
  it('accepts exactly the supported public key algorithms', () => {
    const supported: KasPublicKeyAlgorithm[] = [
      'ec:secp256r1',
      'ec:secp384r1',
      'ec:secp521r1',
      'rsa:2048',
      'rsa:4096',
      'mlkem:512',
      'mlkem:768',
      'mlkem:1024',
    ];

    for (const algorithm of supported) {
      expect(isPublicKeyAlgorithm(algorithm), algorithm).to.equal(true);
    }

    for (const algorithm of [
      '',
      'rsa:1024',
      'rsa:8192',
      'ec:secp256k1',
      'mlkem:256',
      'mlkem:1536',
      'mlkem768',
      'MLKEM:768',
      'foo',
    ]) {
      expect(isPublicKeyAlgorithm(algorithm), algorithm).to.equal(false);
    }
  });
});
