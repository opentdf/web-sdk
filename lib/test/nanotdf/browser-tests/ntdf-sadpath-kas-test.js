describe('NanoTDF SadPath Policy -  Up to kas', () => {
  let temp = createTDFString(tdfSoFar, `${header.kas.hex.join(' ')}`);
  tdfSoFar = tdfSoFar.concat(`${header.kas.hex.join(' ')} `);
  it('should throw policy error', () => {
    expect(() => badfn(temp)).to.throw(Error);
  });
});
