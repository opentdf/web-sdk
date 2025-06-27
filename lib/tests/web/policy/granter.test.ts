import { expect } from '@esm-bundle/chai';
import { plan } from '../../../src/policy/granter.js';
import * as matr from './mock-attrs.js';

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
});
