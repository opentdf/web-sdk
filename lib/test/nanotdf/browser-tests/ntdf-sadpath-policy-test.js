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
