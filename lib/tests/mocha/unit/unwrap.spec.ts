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

  describe('regex pattern variations', () => {
    it('should handle double quotes', () => {
      const htmlPayload = new TextEncoder().encode(
        '<input id="data-input" type="hidden" value="SGVsbG8gV29ybGQ=">'
      );
      const result = unwrapHtml(htmlPayload);
      expect(new TextDecoder().decode(result)).to.equal('Hello World');
    });

    it('should handle single quotes', () => {
      const htmlPayload = new TextEncoder().encode(
        "<input id='data-input' type='hidden' value='SGVsbG8gV29ybGQ='>"
      );
      const result = unwrapHtml(htmlPayload);
      expect(new TextDecoder().decode(result)).to.equal('Hello World');
    });

    it('should handle no quotes', () => {
      const htmlPayload = new TextEncoder().encode(
        '<input id=data-input type=hidden value=SGVsbG8gV29ybGQ=>'
      );
      const result = unwrapHtml(htmlPayload);
      expect(new TextDecoder().decode(result)).to.equal('Hello World');
    });

    it('should handle URL-safe base64 characters', () => {
      const htmlPayload = new TextEncoder().encode(
        '<input id="data-input" type="hidden" value="SGVsbG8tV29ybGQ_">'
      );
      const result = unwrapHtml(htmlPayload);
      expect(new TextDecoder().decode(result)).to.equal('Hello-World?');
    });

    it('should handle additional attributes', () => {
      const htmlPayload = new TextEncoder().encode(
        '<input class="hidden" id="data-input" data-test="value" type="hidden" value="SGVsbG8gV29ybGQ=">'
      );
      const result = unwrapHtml(htmlPayload);
      expect(new TextDecoder().decode(result)).to.equal('Hello World');
    });
  });
});
