/* globals window describe it chai bufferToHex hexToBase64 fixtures_basicExample */
const { expect } = chai;
const { nanotdf, header, payload, signature } = fixtures_basicExample;

//HAPPY PATH TESTS

describe('NanoTDF', () => {
  it('should parse the header', () => {
    const ntdf = window.NanoTDF.from(nanotdf, 'base64', true);
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

// SAD PATH TESTS

let tdfSoFar = '';
const createTDFString = (ogStr, strToConcat) => {
  return `${ogStr} ${strToConcat}`;
};
const badfn = (str) => window.NanoTDF.from(hexToBase64(str), 'base64');

describe('NanoTDF SadPath Policy -  Only Magic Num', () => {
  let temp = createTDFString(tdfSoFar, `${header.magicNumberVersion.join(' ')}`);
  tdfSoFar = tdfSoFar.concat(`${header.magicNumberVersion.join(' ')} `);
  it('should throw policy error', () => {
    expect(() => badfn(temp)).to.throw(Error);
  });
});

describe('NanoTDF SadPath Policy -  Up to kas', () => {
  let temp = createTDFString(tdfSoFar, `${header.kas.hex.join(' ')}`);
  tdfSoFar = tdfSoFar.concat(`${header.kas.hex.join(' ')} `);
  it('should throw policy error', () => {
    expect(() => badfn(temp)).to.throw(Error);
  });
});

describe('NanoTDF SadPath Policy -  up to ecc', () => {
  let temp = createTDFString(tdfSoFar, `${header.eccBindingMode.hex.join(' ')}`);
  tdfSoFar = tdfSoFar.concat(`${header.eccBindingMode.hex.join(' ')} `);
  it('should throw policy error', () => {
    expect(() => badfn(temp)).to.throw(Error);
  });
});

describe('NanoTDF SadPath Policy -  up to symmetric payload', () => {
  let temp = createTDFString(tdfSoFar, `${header.symmetricPayloadConfig.hex.join(' ')}`);
  tdfSoFar = tdfSoFar.concat(`${header.symmetricPayloadConfig.hex.join(' ')} `);
  it('should throw policy error', () => {
    expect(() => badfn(temp)).to.throw(Error);
  });
});

describe('NanoTDF SadPath Policy -  up to policy - mode', () => {
  let temp = createTDFString(tdfSoFar, `${header.remotePolicy.mode.join(' ')}`);
  tdfSoFar = tdfSoFar.concat(`${header.remotePolicy.mode.join(' ')} `);
  it('should throw policy error', () => {
    expect(() => badfn(temp)).to.throw(Error);
  });
});
describe('NanoTDF SadPath Policy -  up to policy - body', () => {
  let temp = createTDFString(tdfSoFar, `${header.remotePolicy.body.join(' ')}`);
  tdfSoFar = tdfSoFar.concat(`${header.remotePolicy.body.join(' ')} `);
  it('should throw policy error', () => {
    expect(() => badfn(temp)).to.throw(Error);
  });
});
describe('NanoTDF SadPath Policy -  up to policy - binding', () => {
  let temp = createTDFString(tdfSoFar, `${header.remotePolicy.binding.join(' ')}`);
  tdfSoFar = tdfSoFar.concat(`${header.remotePolicy.binding.join(' ')} `);
  it('should throw policy error', () => {
    expect(() => badfn(temp)).to.throw(Error);
  });
});

describe('NanoTDF SadPath Policy -  up to ephemeral key', () => {
  let temp = createTDFString(tdfSoFar, `${header.ephemeralPublicKey.join(' ')}`);
  tdfSoFar = tdfSoFar.concat(`${header.ephemeralPublicKey.join(' ')}`);
  it('should throw policy error', () => {
    expect(() => badfn(temp)).to.throw(Error);
  });
});

describe('NnoTDF Sadpath - up to Payload - length', () => {
  let temp = createTDFString(tdfSoFar, `${payload.length.join(' ')}`);
  tdfSoFar = tdfSoFar + `${payload.length.join(' ')} `;
  it('should throw an error', () => {
    expect(() => badfn(temp).to.throw(Error));
  });
});
describe('NnoTDF Sadpath - up to Payload - iv', () => {
  let temp = createTDFString(tdfSoFar, `${payload.iv.join(' ')}`);
  tdfSoFar = tdfSoFar + `${payload.iv.join(' ')} `;
  it('should throw an error', () => {
    expect(() => badfn(temp).to.throw(Error));
  });
});
describe('NnoTDF Sadpath - up to Payload - ciphertext', () => {
  let temp = createTDFString(tdfSoFar, `${payload.ciphertext.join(' ')}`);
  tdfSoFar = tdfSoFar + `${payload.ciphertext.join(' ')} `;
  it('should throw an error', () => {
    expect(() => badfn(temp).to.throw(Error));
  });
});
describe('NnoTDF Sadpath - up to Payload - authtag', () => {
  let temp = createTDFString(tdfSoFar, `${payload.authTag.join(' ')}`);
  tdfSoFar = tdfSoFar + `${payload.authTag.join(' ')} `;
  it('should throw an error', () => {
    expect(() => badfn(temp).to.throw(Error));
  });
});

describe('NnoTDF Sadpath - up to Signature - publickey', () => {
  let temp = createTDFString(tdfSoFar, `${signature.publicKey.join(' ')}`);
  tdfSoFar = tdfSoFar + `${signature.publicKey.join(' ')} `;
  it('should throw an error', () => {
    expect(() => badfn(temp).to.throw(Error));
  });
});
describe('NnoTDF Sadpath - up to Signature - signature', () => {
  let temp = createTDFString(tdfSoFar, `${signature.signature.join(' ')}`);
  tdfSoFar = tdfSoFar + `${signature.signature.join(' ')} `;
  it('should not throw error', () => {
    expect(() => badfn(temp).to.not.throw(Error));
  });
});
