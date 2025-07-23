// tests for assertions.ts


import { expect } from 'chai';

import * as assertions from '../../../tdf3/src/assertions.js';

describe('assertions', () => {
  describe('isAssertionConfig', () => {
    it('validates config', () => {
      expect(
        assertions.isAssertionConfig({
          id: 'assertion1',
          type: 'handling',
          scope: 'tdo',
          appliesToState: 'unencrypted',
          statement: {
            format: 'base64binary',
            schema: 'text',
            value: 'ICAgIDxlZGoOkVkaD4=',
          },
        })
      ).to.be.true;
    });

    it('normalizes assertions', async () => {
      let assertion: any = {
        appliesToState: "unencrypted",
        id: "system-metadata",
        binding: {
          method: "jws",
          signature: "test-signature"
        },
        signingKey: {
          "alg": "ES256",
          "key": new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
        },
        scope: "payload",
        statement: {
          format: "json",
          schema: "system-metadata-v1",
          value: "{\"tdf_spec_version\":\"4.3.0\",\"creation_date\":\"2025-07-23T09:25:51.255364+02:00\",\"operating_system\":\"Mac OS X\",\"sdk_version\":\"Java-0.8.2-SNAPSHOT\",\"java_version\":\"17.0.14\",\"architecture\":\"aarch64\"}"
        },
        type: "other"
      };

      let h1 = await assertions.hash(assertion);
      delete assertion.signingKey;
      let h2 = await assertions.hash(assertion);

      expect(h1).to.equal(h2);
    });
  });
});
