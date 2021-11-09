import { expect } from '@esm-bundle/chai';

import * as hex from '../../src/encodings/hex.js';

describe('hex', function () {
  it('encodes', function () {
    const encodedString = hex.encode('Hello world');
    expect(encodedString).to.eql('48656c6c6f20776f726c64');
  });
  it('decodes', function () {
    const string = hex.decode('466f6f');
    expect(string).to.eql('Foo');
  });
});
