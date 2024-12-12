import { expect } from 'chai';
import { unwrapHtml } from '../../../tdf3/src/utils/unwrap.js';
import { InvalidFileError } from '../../../src/errors.js';

describe('unwrapHtml', () => {
  it('should decode base64 payload from Uint8Array', () => {
    const htmlPayload = new TextEncoder().encode(
      '<input id="data-input" value="SGVsbG8gd29ybGQ=">'
    );
    const result = unwrapHtml(htmlPayload);
    expect(new TextDecoder().decode(result)).to.equal('Hello world');
  });

  it('should throw InvalidFileError if payload is missing', () => {
    const htmlPayload = new TextEncoder().encode(
      '<input id="data-output-or-something" value="SGVsbG8gd29ybGQ=">'
    );
    expect(() => unwrapHtml(htmlPayload)).to.throw(InvalidFileError, 'Payload is missing');
  });

  it('should throw InvalidFileError if there is a problem extracting the payload', () => {
    const htmlPayload = new TextEncoder().encode('<input id="data-input" value="=========">');
    expect(() => unwrapHtml(htmlPayload)).to.throw(
      InvalidFileError,
      'There was a problem extracting the TDF3 payload'
    );
  });
});
