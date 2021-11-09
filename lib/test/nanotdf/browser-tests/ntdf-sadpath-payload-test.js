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
