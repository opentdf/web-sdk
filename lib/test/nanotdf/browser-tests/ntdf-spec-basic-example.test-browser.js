/* globals window describe it chai bufferToHex fixtures_basicExample */
const { expect } = chai;
const { nanotdf, header, payload, signature } = fixtures_basicExample;

describe('NanoTDF', () => {
  it('should parse the header', () => {
    const ntdf = window.NanoTDF.from(nanotdf, 'base64');
    // Header actuals
    const actualMagicNumberVersion = bufferToHex(ntdf.header.magicNumberVersion);
    const actualKas = ntdf.header.kas;
    const actualUseECDSABinding = ntdf.header.useECDSABinding;
    const actualEphemeralCurveName = ntdf.header.ephemeralCurveName;
    const actualHasSignature = ntdf.header.hasSignature;
    const actualSignatureCurveName = ntdf.header.signatureCurveName;
    const actualSymmetricCipher = ntdf.header.symmetricCipher;
    const actualPolicyType = ntdf.header.policy?.type;
    const actualPolicyProtocol = ntdf.header.policy?.remotePolicy?.protocol;
    const actualPolicyUrn = ntdf.header.policy?.remotePolicy?.body;
    const actualPolicyBinding = bufferToHex(ntdf.header.policy?.binding);
    const actualEphemeralPublicKey = bufferToHex(ntdf.header.ephemeralPublicKey);

    // Header Assertions
    expect(actualMagicNumberVersion).to.eql(header.magicNumberVersion);
    expect(actualKas?.protocol).to.equal(header.kas.protocol);
    expect(actualKas?.lengthOfBody).to.equal(header.kas.length);
    expect(actualKas?.body).to.equal(header.kas.body);
    expect(actualUseECDSABinding).to.equal(header.eccBindingMode.useECDSABinding);
    expect(actualEphemeralCurveName).to.equal(header.eccBindingMode.ephemeralCurveName);
    expect(actualHasSignature).to.equal(header.symmetricPayloadConfig.hasSignature);
    expect(actualSignatureCurveName).to.equal(header.symmetricPayloadConfig.signatureCurveName);
    expect(actualSymmetricCipher).to.equal(header.symmetricPayloadConfig.symmetricCipher);
    expect(actualPolicyType).to.equal(header.remotePolicy.type);
    expect(actualPolicyProtocol).to.equal(header.remotePolicy.remotePolicy.protocol);
    expect(actualPolicyUrn).to.equal(header.remotePolicy.remotePolicy.body);
    expect(actualPolicyBinding).to.eql(header.remotePolicy.binding);
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
    const actualPublicKey = bufferToHex(ntdf.signature.publicKey);
    const actualSignature = bufferToHex(ntdf.signature.signature);

    // Payload Assertions
    expect(actualPublicKey).to.eql(signature.publicKey);
    expect(actualSignature).to.eql(signature.signature);

    // NanoTDF Assertions
    const base64NanoTDF = ntdf.toBase64();
    expect(base64NanoTDF).to.eql(nanotdf);
  });
});
