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
    for (const { name, e } of [
      { name: 'UUU', e: [] },
      { name: 'UUG', e: [{ kas: matr.evenMoreSpecificKas, sid: '1' }] },
      { name: 'UGU', e: [{ kas: matr.specifiedKas, sid: '1' }] },
      { name: 'UGG', e: [{ kas: matr.evenMoreSpecificKas, sid: '1' }] },
      { name: 'GUU', e: [{ kas: matr.lessSpecificKas, sid: '1' }] },
      { name: 'GUG', e: [{ kas: matr.evenMoreSpecificKas, sid: '1' }] },
      { name: 'GGU', e: [{ kas: matr.specifiedKas, sid: '1' }] },
      { name: 'GGG', e: [{ kas: matr.evenMoreSpecificKas, sid: '1' }] },
      { name: 'UUU+UUG', e: [{ kas: matr.evenMoreSpecificKas, sid: '1' }] },
    ]) {
      const attrs = matr.valuesFor(
        name.split('+').map((s) => {
          const [n, a, v] = s;
          const ns = n == 'G' ? matr.nsGranted : matr.nsUngranted;
          const attr = `${ns}/attr/${a == 'G' ? '' : 'un'}granted`;
          return `${attr}/value/${v == 'G' ? '' : 'un'}granted`;
        })
      );
      const expected = e.map(({ kas, sid }) => ({ kas: matr.kases[kas], sid }));
      it(name, async () => {
        const p = plan(attrs);
        expect(p).to.deep.equal(expected);
      });
    }
  });
});
