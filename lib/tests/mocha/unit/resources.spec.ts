import { expect } from 'chai';
import { Resources } from '../../../src/index.js';
import type { Resource_AttributeValues } from '../../../src/platform/authorization/v2/authorization_pb.js';

describe('Resource helpers', () => {
  describe('forAttributeValues()', () => {
    it('builds an attributeValues resource with a single FQN', () => {
      const fqn = 'https://example.com/attr/department/value/finance';
      const r = Resources.forAttributeValues(fqn);
      expect(r.resource.case).to.equal('attributeValues');
      const av = r.resource.value as Resource_AttributeValues;
      expect(av.fqns).to.have.lengthOf(1);
      expect(av.fqns[0]).to.equal(fqn);
    });

    it('builds an attributeValues resource with multiple FQNs', () => {
      const fqn1 = 'https://example.com/attr/department/value/finance';
      const fqn2 = 'https://example.com/attr/level/value/public';
      const r = Resources.forAttributeValues(fqn1, fqn2);
      expect(r.resource.case).to.equal('attributeValues');
      const av = r.resource.value as Resource_AttributeValues;
      expect(av.fqns).to.have.lengthOf(2);
      expect(av.fqns[0]).to.equal(fqn1);
      expect(av.fqns[1]).to.equal(fqn2);
    });

    it('builds an attributeValues resource with an empty-string FQN', () => {
      const r = Resources.forAttributeValues('');
      expect(r.resource.case).to.equal('attributeValues');
      const av = r.resource.value as Resource_AttributeValues;
      expect(av.fqns).to.have.lengthOf(1);
      expect(av.fqns[0]).to.equal('');
    });
  });

  describe('forRegisteredResourceValueFqn()', () => {
    for (const fqn of ['https://example.com/attr/department/value/finance', '']) {
      it(`builds a registeredResourceValueFqn resource with fqn="${fqn}"`, () => {
        const r = Resources.forRegisteredResourceValueFqn(fqn);
        expect(r.resource.case).to.equal('registeredResourceValueFqn');
        expect(r.resource.value).to.equal(fqn);
      });
    }
  });
});
