describe('NanoTDF SadPath Policy -  up to ephemeral key', () => {
  let temp = createTDFString(tdfSoFar, `${header.ephemeralPublicKey.join(' ')}`);
  tdfSoFar = tdfSoFar.concat(`${header.ephemeralPublicKey.join(' ')}`);
  it('should throw policy error', () => {
    expect(() => badfn(temp)).to.throw(Error);
  });
});
