describe('NanoTDF SadPath Policy -  up to ecc', () => {
  let temp = createTDFString(tdfSoFar, `${header.eccBindingMode.hex.join(' ')}`);
  tdfSoFar = tdfSoFar.concat(`${header.eccBindingMode.hex.join(' ')} `);
  it('should throw policy error', () => {
    expect(() => badfn(temp)).to.throw(Error);
  });
});
