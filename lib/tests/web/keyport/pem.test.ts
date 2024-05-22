import { expect } from '@esm-bundle/chai';
import { addNewLines } from '../../../src/keyport/pem.js';

describe('addNewLines', () => {
  it('undefined', () => {
    // @ts-expect-error rstrip requires parameters
    expect(addNewLines()).to.be.undefined;
  });
  it('empty', () => {
    expect(addNewLines('')).to.eql('');
  });
  it('short', () => {
    expect(addNewLines('a')).to.eql('a\r\n');
  });
  it('blank', () => {
    expect(addNewLines(' '.repeat(64))).to.eql(
      '                                                                \r\n'
    );
  });
  it('leftovers', () => {
    expect(addNewLines(' '.repeat(65))).to.eql(
      '                                                                \r\n \r\n'
    );
  });
});
