import { assert } from 'chai';

import { AttributeSet } from '../../src/models/index.js';
import getMocks from '../../mocks/index.js';

const Mocks = getMocks();

describe('AttributeSet', function () {
  it('should construct with zero entries', () => {
    const aSet = new AttributeSet();
    assert(aSet instanceof AttributeSet);
    assert.isArray(aSet.attributes);
    assert.equal(aSet.attributes.length, 0);
    assert.deepEqual(aSet.getDefault(), null);
  });

  it('should add a well-formed attribute object', () => {
    const aSet = new AttributeSet();
    const expected = Mocks.createAttribute({});
    aSet.addAttribute(expected);
    assert.equal(aSet.attributes.length, 1);
    assert.equal(aSet.attributes[0], expected);
    assert.deepEqual(aSet.getDefault(), null);
  });

  it('should add a well-formed default attribute object', () => {
    const aSet = new AttributeSet();
    const expected = Mocks.createAttribute({
      isDefault: true,
    });
    aSet.addAttribute(expected);
    assert.equal(aSet.attributes.length, 1);
    assert.equal(aSet.attributes[0], expected);
    assert.deepEqual(aSet.getDefault(), expected);
  });

  it('should delete an attribute by URL', () => {
    const attributeUrl = 'https://alpha.com/attr/somename/value/somevalue';
    const aSet = new AttributeSet();
    const attr = Mocks.createAttribute({
      attribute: attributeUrl,
    });
    aSet.addAttribute(attr);
    const actual = aSet.deleteAttribute(attributeUrl);
    assert.deepEqual(actual, attr);
    assert.equal(aSet.attributes.length, 0);
  });

  it('overwrites the previous default attribute (only the last in is used)', () => {
    const firstUrl = 'https://first.com/attr/default/value/default';
    const secondUrl = 'https://second.com/attr/default/value/default';
    const first = Mocks.createAttribute({
      isDefault: true,
      attribute: firstUrl,
    });
    const second = Mocks.createAttribute({
      isDefault: true,
      attribute: secondUrl,
    });
    const aSet = new AttributeSet();
    const unactual = aSet.addAttribute(first);
    assert.deepEqual(unactual, first);
    const actual = aSet.addAttribute(second);
    assert.deepEqual(actual, second);
    // Adding the second attribute should remove the first as only one
    // default attribute should exist at a time in the AttributeSet.
    assert.equal(aSet.attributes.length, 1);
    assert.equal(aSet.attributes[0].attribute, secondUrl);
    assert.equal(aSet.getDefault()?.attribute, secondUrl);
  });

  it('should verify that an attribute is in the set', () => {
    const aSet = new AttributeSet();
    const expected = Mocks.createAttribute({});
    aSet.addAttribute(expected);
    assert.isTrue(aSet.has(expected.attribute));
    assert.isFalse(aSet.has('https://some.com/attr/uknown/value/impostor'));
  });

  it('should not duplicate one that already exists (idempotent)', () => {
    const aSet = new AttributeSet();
    const expected = Mocks.createAttribute({});
    expected.attribute = 'https://example.com/attr/test-case/value/bar';
    const actual0 = aSet.addAttribute(expected);
    assert.deepEqual(actual0, expected);
    const actual1 = aSet.addAttribute(expected);
    assert.deepEqual(actual1, null);
    assert.equal(aSet.attributes.length, 1);
    assert.equal(aSet.attributes[0], expected);
  });

  it('should not add one with additional fields (malformed)', () => {
    const aSet = new AttributeSet();
    const expected = Mocks.createAttribute({});
    expected.addedField = 'Potential mallware';
    const actual = aSet.addAttribute(expected);
    assert.deepEqual(actual, null);
    assert.equal(aSet.attributes.length, 0);
  });

  it('should not add a different attributeObject with the same url', () => {
    const aSet = new AttributeSet();
    const expected = Mocks.createAttribute({});
    aSet.addAttribute(expected);
    // Should not add even if the displayName is different
    const unexpected0 = Mocks.createAttribute({
      displayName: 'Some other display name',
    });
    const actual0 = aSet.addAttribute(unexpected0);
    assert.deepEqual(actual0, null);
    // Should not add even if the pubKey is different
    const unexpected1 = Mocks.createAttribute({
      pubKey: 'Some other public key',
    });
    const actual1 = aSet.addAttribute(unexpected1);
    assert.deepEqual(actual1, null);
    // Should not add even if the kasUrl is different
    const unexpected2 = Mocks.createAttribute({
      kasUrl: 'Some other kas url',
    });
    const actual2 = aSet.addAttribute(unexpected2);
    assert.deepEqual(actual2, null);
    // Check to see that the original attribute is intact
    assert.equal(aSet.attributes.length, 1);
    assert.equal(aSet.attributes[0], expected);
  });

  it('should add an attribute object with optional "displayName" missing', () => {
    const aSet = new AttributeSet();
    const expected = Mocks.createAttribute({});
    delete expected.displayName;
    aSet.addAttribute(expected);
    assert.equal(aSet.attributes.length, 1);
    assert.equal(aSet.attributes[0], expected);
  });

  it('should not add an attribute object with "attribute" missing ', () => {
    const aSet = new AttributeSet();
    const expected = Mocks.createAttribute({});
    delete expected.attribute;
    aSet.addAttribute(expected);
    assert.equal(aSet.attributes.length, 0);
  });

  it('should not add an attribute object with "pubKey" missing ', () => {
    const aSet = new AttributeSet();
    const expected = Mocks.createAttribute({});
    delete expected.pubKey;
    aSet.addAttribute(expected);
    assert.equal(aSet.attributes.length, 0);
  });

  it('should not add an attribute object with "kasUrl" missing ', () => {
    const aSet = new AttributeSet();
    const expected = Mocks.createAttribute({});
    delete expected.kasUrl;
    aSet.addAttribute(expected);
    assert.equal(aSet.attributes.length, 0);
  });

  it('should add a list of well-formed attribute objects', async () => {
    const aSet = new AttributeSet();
    const expected0 = Mocks.createAttribute({
      attribute: 'https://example.com/attr/test-case/value/bar-0',
    });
    const expected1 = Mocks.createAttribute({
      attribute: 'https://example.com/attr/test-case/value/bar-1',
    });
    const expected2 = Mocks.createAttribute({
      attribute: 'https://example.com/attr/test-case/value/bar-2',
    });

    const actuals = aSet.addAttributes([expected0, expected1, expected2]);

    assert.equal(actuals.length, 3);
    assert.deepInclude(actuals, expected0);
    assert.deepInclude(actuals, expected1);
    assert.deepInclude(actuals, expected2);
    assert.equal(aSet.attributes.length, 3);
    assert.deepInclude(aSet.attributes, expected0);
    assert.deepInclude(aSet.attributes, expected1);
    assert.deepInclude(aSet.attributes, expected2);
  });

  it('should return a list of all the urls', async () => {
    const url0 = 'https://example.com/attr/test-case/value/bar-0';
    const url1 = 'https://example.com/attr/test-case/value/bar-1';
    const url2 = 'https://example.com/attr/test-case/value/bar-2';
    const expected = [url0, url1, url2];
    const attrs = expected.map((url) => Mocks.createAttribute({ attribute: url }));
    const aSet = new AttributeSet();
    aSet.addAttributes(attrs);
    const actual = aSet.getUrls();
    assert.equal(actual.length, 3);
    expected.forEach((url) => {
      assert.include(actual, url);
    });
  });

  it('should get a known attribute by url', async () => {
    const aSet = new AttributeSet();
    const attribute = 'https://example.com/attr/test-case/value/bar';
    const expected = Mocks.createAttribute({ attribute });
    aSet.addAttribute(expected);
    assert.deepEqual(aSet.get(attribute), expected);
  });

  it('should not get an unknown attribute by url', async () => {
    const aSet = new AttributeSet();
    assert.deepEqual(aSet.get('unknown URL'), null);
  });
});
