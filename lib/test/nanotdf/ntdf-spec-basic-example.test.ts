/* eslint @typescript-eslint/ban-ts-comment: "off" */

import { expect } from '@esm-bundle/chai';
import { NanoTDF } from '../../src/nanotdf/index.js';
import PolicyTypeEnum from '../../src/nanotdf/enum/PolicyTypeEnum.js';
import bufferToHex from './helpers/bufferToHex.js';
import * as remoteFixture from '../../src/__fixtures__/nanotdf-spec-remote-example.js';

import * as embeddedFixture from '../../src/__fixtures__/nanotdf-spec-embedded-example.js';
import * as plainEmbeddedFixture from '../../src/__fixtures__/nanotdf-spec-plain-embedded-example.js';

describe('NanoTDF', () => {
  for (const { policyType, fixture } of [
    { policyType: 'remote', fixture: remoteFixture },
    { policyType: 'embedded', fixture: embeddedFixture },
    { policyType: 'plain-embedded', fixture: plainEmbeddedFixture },
  ]) {
    const { nanotdf, header, payload, signature } = fixture;
    it(`should parse the header from ${policyType} policy`, () => {
      const { useECDSABinding, ephemeralCurveName } = header.eccBindingMode;
      const { hasSignature, signatureCurveName, symmetricCipher } = header.symmetricPayloadConfig;

      const ntdf = NanoTDF.from(nanotdf, NanoTDF.Encodings.Base64, true);

      // Header actuals
      const actualMagicNumberVersion = bufferToHex(ntdf.header.magicNumberVersion);
      const actualKas = ntdf.header.kas;
      const actualUseECDSABinding = ntdf.header.useECDSABinding;
      const actualEphemeralCurveName = ntdf.header.ephemeralCurveName;
      const actualHasSignature = ntdf.header.hasSignature;
      const actualSignatureCurveName = ntdf.header.signatureCurveName;
      const actualSymmetricCipher = ntdf.header.symmetricCipher;
      const actualEphemeralPublicKey = bufferToHex(ntdf.header.ephemeralPublicKey);

      const actualPolicyType = ntdf.header.policy?.type;
      const actualPolicyProtocol = ntdf.header.policy?.remotePolicy?.protocol;
      const actualPolicyUrn = ntdf.header.policy?.remotePolicy?.body;
      const actualPolicyContent = bufferToHex(ntdf.header.policy?.content);
      const actualPolicyBinding = bufferToHex(ntdf.header.policy?.binding);

      let policyProtocol;
      let policyUrn;
      let policyContent;
      switch (header.policy.type) {
        case PolicyTypeEnum.Remote:
          // @ts-ignore
          policyProtocol = header.policy.remotePolicy.protocol;
          // @ts-ignore
          policyUrn = header.policy.remotePolicy.body;
          break;
        case PolicyTypeEnum.EmbeddedEncrypted:
          // @ts-ignore
          policyContent = header.policy.content;
          break;
        case PolicyTypeEnum.EmbeddedText:
          // @ts-ignore
          policyContent = header.policy.content;
          break;
      }

      // Header Assertions
      expect(actualMagicNumberVersion).to.eql(header.magicNumberVersion);
      expect(actualKas?.protocol).to.eql(header.kas.protocol);
      expect(actualKas?.lengthOfBody).to.eql(header.kas.length);
      expect(actualKas?.body).to.eql(header.kas.body);
      expect(actualUseECDSABinding).to.eql(useECDSABinding);
      expect(actualEphemeralCurveName).to.eql(ephemeralCurveName);
      expect(actualHasSignature).to.eql(hasSignature);
      expect(actualSignatureCurveName).to.eql(signatureCurveName);
      expect(actualSymmetricCipher).to.eql(symmetricCipher);
      expect(actualPolicyType).to.eql(header.policy.type);
      expect(actualPolicyProtocol).to.eql(policyProtocol);
      expect(actualPolicyUrn).to.eql(policyUrn);
      expect(actualPolicyContent).to.eql(policyContent);
      expect(actualPolicyBinding).to.eql(header.policy.binding);
      expect(actualEphemeralPublicKey).to.eql(header.ephemeralPublicKey);

      // Payload actuals
      const actualIV = bufferToHex(ntdf.payload.iv);
      const actualCiphertext = bufferToHex(ntdf.payload.ciphertext);
      const actualAuthTag = bufferToHex(ntdf.payload.authTag);

      // Payload Assertions
      expect(actualIV).to.eql(payload.iv);
      expect(actualCiphertext).to.eql(payload.ciphertext);
      expect(actualAuthTag).to.eql(payload.authTag);

      // Payload actuals
      const actualPublicKey = bufferToHex(ntdf.signature?.publicKey);
      const actualSignature = bufferToHex(ntdf.signature?.signature);

      // Payload Assertions
      expect(actualPublicKey).to.eql(signature.publicKey);
      expect(actualSignature).to.eql(signature.signature);

      // NanoTDF Assertions
      const base64NanoTDF = ntdf.toBase64();
      const nanotdfStr = nanotdf.replace(/(\r\n|\n|\r)/gm, '');
      expect(base64NanoTDF).to.eql(nanotdfStr);
    });
  }
});
