describe('NanoTDF SadPath Policy -  up to symmetric payload', () => {
  let temp = createTDFString(tdfSoFar, `${header.symmetricPayloadConfig.hex.join(' ')}`);
  tdfSoFar = tdfSoFar.concat(`${header.symmetricPayloadConfig.hex.join(' ')} `);
  it('should throw policy error', () => {
    expect(() => badfn(temp)).to.throw(Error);
  });
});
