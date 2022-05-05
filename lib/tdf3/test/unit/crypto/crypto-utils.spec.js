import { assert, expect } from 'chai';

import {
  formatAsPem,
  isValidAsymmetricKeySize,
  removePemFormatting,
} from '../../../src/crypto/crypto-utils';

describe('crypto-utils', () => {
  it('should remove pem formatting', () => {
    const pubKey = `-----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEBTlf8Gvvyu4xlxr16F1I6
    4eApCTrMJHejKDxm0GohB9pQPd/5ZMEu433KtdM03Q0/EwUuy+XugXAGA9PJx2c9
    y1pUFDsSpVoQt4epU2pc3pD17zxVLoNm5b2wnZlb+E7p9cBN/hjcg15XOaML+IYO
    3mLbZ/2KaagrymsK74lKQbmhtVAwz75yu1atMCeGpbsLLLvdzLkSMNF3OPdNSwHF
    uG2md36lhoqyCsk4N3YMPSD4d1xdBl7yRplptow6mSSoC4utzkJX0AhEmvlY6cuS
    4c3hnLFHPygS6B51yuGMXWb92mpXSA4VGy5ni44QPXsmrWeX1ITUihKzAotNJ0Tu
    GwIDAQAB
    -----END PUBLIC KEY-----`;

    const formatted = removePemFormatting(pubKey);
    assert.equal(
      formatted,
      `    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEBTlf8Gvvyu4xlxr16F1I6    4eApCTrMJHejKDxm0GohB9pQPd/5ZMEu433KtdM03Q0/EwUuy+XugXAGA9PJx2c9    y1pUFDsSpVoQt4epU2pc3pD17zxVLoNm5b2wnZlb+E7p9cBN/hjcg15XOaML+IYO    3mLbZ/2KaagrymsK74lKQbmhtVAwz75yu1atMCeGpbsLLLvdzLkSMNF3OPdNSwHF    uG2md36lhoqyCsk4N3YMPSD4d1xdBl7yRplptow6mSSoC4utzkJX0AhEmvlY6cuS    4c3hnLFHPygS6B51yuGMXWb92mpXSA4VGy5ni44QPXsmrWeX1ITUihKzAotNJ0Tu    GwIDAQAB    `
    );
  });

  it('is valid asymmetric key size', () => {
    expect(isValidAsymmetricKeySize(undefined)).to.be.true;
    expect(isValidAsymmetricKeySize(1)).to.be.true;
    expect(isValidAsymmetricKeySize(1, 2)).to.be.false;
    expect(isValidAsymmetricKeySize('null')).to.be.false;
  });

  it('should format as pem', () => {
    const label = 'PUBLIC KEY';
    const data = 'hello world';
    const buff = Buffer.from(data);
    const base64str = buff.toString('base64');

    const result = `-----BEGIN PUBLIC KEY-----aGVsbG8gd29ybGQ=-----END PUBLIC KEY-----`;

    expect(formatAsPem(base64str, label).trim().replace(/\n/g, '')).to.equal(result);
  });
});
