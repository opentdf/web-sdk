import { expect } from 'chai';
import {
  rewrapAdditionalContextHeader,
  type RewrapAdditionalContext,
} from '../../../src/access.js';
import { base64 } from '../../../src/encodings/index.js';

describe('rewrapAdditionalContextHeader', () => {
  it('should return undefined for empty array', () => {
    const result = rewrapAdditionalContextHeader([]);
    expect(result).to.be.undefined;
  });

  it('should return base64 encoded header for single FQN', () => {
    const fqns = ['https://example.com/obl/drm/value/mask'];
    const result = rewrapAdditionalContextHeader(fqns);

    expect(result).to.be.a('string');

    // Decode and verify structure
    const decoded = JSON.parse(base64.decode(result!)) as RewrapAdditionalContext;
    expect(decoded).to.have.property('obligations');
    expect(decoded.obligations).to.have.property('fulfillableFQNs');
    expect(decoded.obligations.fulfillableFQNs).to.deep.equal([
      'https://example.com/obl/drm/value/mask',
    ]);
  });

  it('should lowercase all FQNs', () => {
    const fqns = [
      'https://EXAMPLE.com/obl/DRM-TEST/value/MASK-123',
      'https://example.COM/obl/water_mark/VALUE/apply_now',
    ];
    const result = rewrapAdditionalContextHeader(fqns);

    expect(result).to.be.a('string');

    // Decode and verify FQNs are lowercased
    const decoded = JSON.parse(base64.decode(result!)) as RewrapAdditionalContext;
    expect(decoded.obligations.fulfillableFQNs).to.deep.equal([
      'https://example.com/obl/drm-test/value/mask-123',
      'https://example.com/obl/water_mark/value/apply_now',
    ]);
  });

  it('should produce valid JSON structure', () => {
    const fqns = ['https://example.com/obl/test/value/v1'];
    const result = rewrapAdditionalContextHeader(fqns);

    expect(result).to.be.a('string');

    // Verify it's valid base64
    expect(() => base64.decode(result!)).to.not.throw();

    // Verify decoded value is valid JSON
    const decoded = base64.decode(result!);
    expect(() => JSON.parse(decoded)).to.not.throw();

    // Verify structure
    const parsed = JSON.parse(decoded) as RewrapAdditionalContext;
    expect(parsed).to.have.property('obligations');
    expect(parsed.obligations).to.have.property('fulfillableFQNs');
    expect(parsed.obligations.fulfillableFQNs).to.be.an('array');
  });
});
