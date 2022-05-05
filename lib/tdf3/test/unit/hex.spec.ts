import { expect } from 'chai';
import { hex } from '../../src/encodings';

describe('hex', function () {
  it('encodes', function () {
    const encodedString = hex.encode('Hello world');
    expect(encodedString).to.equal('48656c6c6f20776f726c64');
  });
  it('decodes', function () {
    const string = hex.decode('466f6f');
    expect(string).to.equal('Foo');
  });
});
