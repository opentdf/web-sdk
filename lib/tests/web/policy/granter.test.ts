import { expect } from '@esm-bundle/chai';
import { create } from '@bufbuild/protobuf';
import { plan } from '../../../src/policy/granter.js';
import { AttributeRuleType } from '../../../src/policy/attributes.js';
import * as matr from './mock-attrs.js';
import {
  Algorithm,
  AttributeSchema,
  NamespaceSchema,
  SimpleKasKeySchema,
  SimpleKasPublicKeySchema,
  ValueSchema,
} from '../../../src/platform/policy/objects_pb.js';
import { kasPublicKey } from '../../mocks/pems.js';

const makeSimpleKasKey = (kasUri: string, kid: string) =>
  create(SimpleKasKeySchema, {
    kasUri,
    kasId: kasUri,
    publicKey: create(SimpleKasPublicKeySchema, {
      algorithm: Algorithm.RSA_2048,
      kid,
      pem: kasPublicKey,
    }),
  });

const buildValue = ({
  valueKasKeys = [],
  attributeKasKeys = [],
  namespaceKasKeys = [],
  grants = [],
  namespaceFqn = 'https://kaskeys.ns',
  attributeName = 'test',
  valueName = 'test',
}: {
  valueKasKeys?: ReturnType<typeof makeSimpleKasKey>[];
  attributeKasKeys?: ReturnType<typeof makeSimpleKasKey>[];
  namespaceKasKeys?: ReturnType<typeof makeSimpleKasKey>[];
  grants?: typeof matr.kases[keyof typeof matr.kases][];
  namespaceFqn?: string;
  attributeName?: string;
  valueName?: string;
}) => {
  const namespace = create(NamespaceSchema, {
    fqn: namespaceFqn,
    name: 'kaskeys',
    active: true,
    id: '',
    grants: [],
    kasKeys: namespaceKasKeys,
    rootCerts: [],
  });
  const attribute = create(AttributeSchema, {
    fqn: `${namespace.fqn}/attr/${attributeName}`,
    name: attributeName,
    namespace,
    active: true,
    id: '',
    rule: AttributeRuleType.UNSPECIFIED,
    values: [],
    grants: [],
    kasKeys: attributeKasKeys,
  });
  return create(ValueSchema, {
    fqn: `${attribute.fqn}/value/${valueName}`,
    value: valueName,
    attribute,
    active: true,
    id: '',
    kasKeys: valueKasKeys,
    resourceMappings: [],
    subjectMappings: [],
    grants,
    obligations: [],
  });
};

describe('policy/granter', () => {
  describe('constructs kao template', () => {
    for (const { name, attrs, e } of [
      { name: 'one actual', attrs: [matr.valRelAus], e: [{ kas: matr.kasAu, sid: '1' }] },
      {
        name: 'one actual with default',
        attrs: [matr.valClassA, matr.valRelAus],
        e: [{ kas: matr.kasAu, sid: '1' }],
      },
      { name: 'one defaulted attr default', attrs: [matr.valClassA], e: [] },
      { name: 'empty policy', attrs: [], e: [] },
      {
        name: 'shares',
        attrs: [matr.valRelAus, matr.valRelCan, matr.valRelUsa],
        e: [matr.kasAu, matr.kasCa, matr.kasUs].map((kas) => ({ kas, sid: '1' })),
      },
      {
        name: 'splits',
        attrs: [matr.valN2KHCS, matr.valN2KSI],
        e: [
          { kas: matr.kasUsHCS, sid: '1' },
          { kas: matr.kasUsSA, sid: '2' },
        ],
      },
      {
        name: 'simplifies two with a default',
        attrs: [matr.valClassS, matr.valRelGbr, matr.valN2KINT],
        e: [{ kas: matr.kasUk, sid: '1' }],
      },
      {
        name: 'compartments',
        attrs: [matr.valClassS, matr.valRelGbr, matr.valRelUsa, matr.valN2KHCS, matr.valN2KSI],
        e: [
          { kas: matr.kasUsHCS, sid: '1' },
          { kas: matr.kasUk, sid: '2' },
          { kas: matr.kasUs, sid: '2' },
          { kas: matr.kasUsSA, sid: '3' },
        ],
      },
    ]) {
      const expected = e.map(({ kas, sid }) => ({ kas: matr.kases[kas], sid }));
      it(name, async () => {
        const p = plan(matr.valuesFor(attrs));
        expect(p).to.deep.equal(expected);
      });
    }
  });

  describe('grant overloading', () => {
    for (const { attrs, expectedPlan } of [
      {
        attrs: [{ fqn: `${matr.nsUngranted}/attr/ungranted/value/ungranted` }],
        expectedPlan: [],
      },
      {
        attrs: [{ fqn: `${matr.nsUngranted}/attr/ungranted/value/granted` }],
        expectedPlan: [
          { kas: matr.kases[matr.evenMoreSpecificKas], sid: '1', kid: 'e1' },
          { kas: matr.kases[matr.evenMoreSpecificKas], sid: '1', kid: 'r1' },
        ],
      },
      {
        attrs: [{ fqn: `${matr.nsUngranted}/attr/granted/value/ungranted` }],
        expectedPlan: [
          { kas: matr.kases[matr.specifiedKas], sid: '1', kid: 'e1' },
          { kas: matr.kases[matr.specifiedKas], sid: '1', kid: 'r1' },
        ],
      },
      {
        attrs: [{ fqn: `${matr.nsUngranted}/attr/granted/value/granted` }],
        expectedPlan: [
          { kas: matr.kases[matr.evenMoreSpecificKas], sid: '1', kid: 'e1' },
          { kas: matr.kases[matr.evenMoreSpecificKas], sid: '1', kid: 'r1' },
        ],
      },
      {
        attrs: [{ fqn: `${matr.nsGranted}/attr/ungranted/value/ungranted` }],
        expectedPlan: [
          { kas: matr.kases[matr.lessSpecificKas], sid: '1', kid: 'e1' },
          { kas: matr.kases[matr.lessSpecificKas], sid: '1', kid: 'r1' },
        ],
      },
      {
        attrs: [{ fqn: `${matr.nsGranted}/attr/ungranted/value/granted` }],
        expectedPlan: [
          { kas: matr.kases[matr.evenMoreSpecificKas], sid: '1', kid: 'e1' },
          { kas: matr.kases[matr.evenMoreSpecificKas], sid: '1', kid: 'r1' },
        ],
      },
      {
        attrs: [{ fqn: `${matr.nsGranted}/attr/granted/value/ungranted` }],
        expectedPlan: [
          { kas: matr.kases[matr.specifiedKas], sid: '1', kid: 'e1' },
          { kas: matr.kases[matr.specifiedKas], sid: '1', kid: 'r1' },
        ],
      },
      {
        attrs: [{ fqn: `${matr.nsGranted}/attr/granted/value/granted` }],
        expectedPlan: [
          { kas: matr.kases[matr.evenMoreSpecificKas], sid: '1', kid: 'e1' },
          { kas: matr.kases[matr.evenMoreSpecificKas], sid: '1', kid: 'r1' },
        ],
      },
      {
        attrs: [
          { fqn: `${matr.nsUngranted}/attr/ungranted/value/ungranted` },
          { fqn: `${matr.nsUngranted}/attr/ungranted/value/granted` },
        ],
        expectedPlan: [
          { kas: matr.kases[matr.evenMoreSpecificKas], sid: '1', kid: 'e1' },
          { kas: matr.kases[matr.evenMoreSpecificKas], sid: '1', kid: 'r1' },
        ],
      },
    ]) {
      const name = attrs.map((attr) => attr.fqn).join('+');
      it.only(name, async () => {
        const platformAttrs = attrs.map((attr) => matr.valueFor(attr.fqn));
        const p = plan(platformAttrs);
        expect(p).to.deep.equal(expectedPlan);
      });
    }
  });

  describe('kasKeys precedence', () => {
    it('uses value kasKeys over attribute and namespace', async () => {
      const valueKey = makeSimpleKasKey('https://kas.value/', 'v1');
      const attributeKey = makeSimpleKasKey('https://kas.attribute/', 'a1');
      const namespaceKey = makeSimpleKasKey('https://kas.namespace/', 'n1');
      const value = buildValue({
        valueKasKeys: [valueKey],
        attributeKasKeys: [attributeKey],
        namespaceKasKeys: [namespaceKey],
      });
      const kas = Object.assign({ kasUri: valueKey.kasUri }, valueKey.publicKey);
      expect(plan([value])).to.deep.equal([{ kas, sid: '1', kid: 'v1' }]);
    });

    it('uses attribute kasKeys when value has none', async () => {
      const attributeKey = makeSimpleKasKey('https://kas.attribute/', 'a1');
      const namespaceKey = makeSimpleKasKey('https://kas.namespace/', 'n1');
      const value = buildValue({
        attributeKasKeys: [attributeKey],
        namespaceKasKeys: [namespaceKey],
      });
      const kas = Object.assign({ kasUri: attributeKey.kasUri }, attributeKey.publicKey);
      expect(plan([value])).to.deep.equal([{ kas, sid: '1', kid: 'a1' }]);
    });

    it('uses namespace kasKeys when value and attribute have none', async () => {
      const namespaceKey = makeSimpleKasKey('https://kas.namespace/', 'n1');
      const value = buildValue({
        namespaceKasKeys: [namespaceKey],
      });
      const kas = Object.assign({ kasUri: namespaceKey.kasUri }, namespaceKey.publicKey);
      expect(plan([value])).to.deep.equal([{ kas, sid: '1', kid: 'n1' }]);
    });

    it('uses grants when no kasKeys are present', async () => {
      const value = buildValue({
        grants: [matr.kases[matr.specifiedKas]],
      });
      expect(plan([value])).to.deep.equal([
        { kas: matr.kases[matr.specifiedKas], sid: '1', kid: 'e1' },
        { kas: matr.kases[matr.specifiedKas], sid: '1', kid: 'r1' },
      ]);
    });

    it('handles multiple values with per-value kasKeys', async () => {
      const valueKeyA = makeSimpleKasKey('https://kas.a/', 'a1');
      const valueKeyB = makeSimpleKasKey('https://kas.b/', 'b1');
      const valueA = buildValue({
        valueKasKeys: [valueKeyA],
        attributeName: 'multi',
        valueName: 'a',
      });
      const valueB = buildValue({
        valueKasKeys: [valueKeyB],
        attributeName: 'multi',
        valueName: 'b',
      });
      const kasA = Object.assign({ kasUri: valueKeyA.kasUri }, valueKeyA.publicKey);
      const kasB = Object.assign({ kasUri: valueKeyB.kasUri }, valueKeyB.publicKey);
      expect(plan([valueA, valueB])).to.deep.equal([
        { kas: kasA, sid: '1', kid: 'a1' },
        { kas: kasB, sid: '2', kid: 'b1' },
      ]);
    });
  });
});
