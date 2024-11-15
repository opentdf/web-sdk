import { allPool, anyPool } from '../../../src/concurrency.js';
import { expect } from 'chai';

describe('concurrency', () => {
  for (const n of [1, 2, 3, 4]) {
    describe(`allPool(${n})`, () => {
      it(`should resolve all promises with a pool size of ${n}`, async () => {
        const promises = {
          a: Promise.resolve(1),
          b: Promise.resolve(2),
          c: Promise.resolve(3),
        };
        const result = await allPool(n, promises);
        expect(result).to.have.members([1, 2, 3]);
      });
      it(`should reject if any promise rejects, n=${n}`, async () => {
        const promises = {
          a: Promise.resolve(1),
          b: Promise.reject(new Error('failure')),
          c: Promise.resolve(3),
        };
        try {
          await allPool(n, promises);
        } catch (e) {
          expect(e).to.contain({ message: 'failure' });
        }
      });
    });
    describe(`anyPool(${n})`, () => {
      it('should resolve with the first resolved promise', async () => {
        const startTime = Date.now();
        const promises = {
          a: new Promise((resolve) => setTimeout(() => resolve(1), 500)),
          b: new Promise((resolve) => setTimeout(() => resolve(2), 50)),
          c: new Promise((resolve) => setTimeout(() => resolve(3), 1500)),
        };
        const result = await anyPool(n, promises);
        const endTime = Date.now();
        const elapsed = endTime - startTime;
        if (n > 1) {
          expect(elapsed).to.be.lessThan(500);
          expect(result).to.equal(2);
        } else {
          expect(elapsed).to.be.greaterThan(50);
          expect(elapsed).to.be.lessThan(1000);
          expect(result).to.equal(1);
        }
      });

      it('should reject if all promises reject', async () => {
        const promises = {
          a: Promise.reject(new Error('failure1')),
          b: Promise.reject(new Error('failure2')),
          c: Promise.reject(new Error('failure3')),
        };
        try {
          await anyPool(n, promises);
        } catch (e) {
          expect(e).to.be.instanceOf(AggregateError);
          expect(e.errors).to.have.lengthOf(3);
        }
      });
    });
  }
});
