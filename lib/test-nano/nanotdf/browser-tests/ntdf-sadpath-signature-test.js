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
