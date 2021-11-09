let tdfSoFar = '';
const createTDFString = (ogStr, strToConcat) => {
  return `${ogStr} ${strToConcat}`;
};
const badfn = (str) => window.NanoTDF.from(hexToBase64(str), 'base64');

describe('NanoTDF SadPath Policy -  Only Magic Num', () => {
  let temp = createTDFString(tdfSoFar, `${header.magicNumberVersion.join(' ')}`);
  tdfSoFar = tdfSoFar.concat(`${header.magicNumberVersion.join(' ')} `);
  it('should throw policy error', () => {
    expect(() => badfn(temp)).to.throw();
  });
});
