import { expect } from 'chai';

import { ByteAccumulator } from '../../../tdf3/src/utils/byte-accumulator.js';

/** Reference implementation: the array-of-arrays join this replaces. */
function concatenate(runs: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(runs.reduce((total, run) => total + run.length, 0));
  let offset = 0;
  for (const run of runs) {
    out.set(run, offset);
    offset += run.length;
  }
  return out;
}

function digest(seed: number, size: number): Uint8Array {
  return Uint8Array.from({ length: size }, (_, i) => (seed * 31 + i) & 0xff);
}

describe('ByteAccumulator', () => {
  it('starts empty', () => {
    const acc = new ByteAccumulator();
    expect(acc.length).to.equal(0);
    expect(acc.subarray()).to.deep.equal(new Uint8Array(0));
  });

  it('matches a plain concatenation, sized or not', () => {
    for (const runCount of [1, 2, 3, 17, 100]) {
      for (const runSize of [1, 16, 32]) {
        const runs = Array.from({ length: runCount }, (_, i) => digest(i, runSize));
        const expected = concatenate(runs);

        for (const hint of [0, expected.length, 8]) {
          const acc = new ByteAccumulator(hint);
          runs.forEach((run) => acc.push(run));
          expect(acc.length, `${runCount}x${runSize} hint=${hint}`).to.equal(expected.length);
          expect(acc.subarray(), `${runCount}x${runSize} hint=${hint}`).to.deep.equal(expected);
        }
      }
    }
  });

  // The exact-size hint is the whole reason the constructor takes one: it is
  // what keeps the 105 MB of digests at 50 TiB from transiently costing 3x that.
  it('does not reallocate when the expected size is known and correct', () => {
    const runs = Array.from({ length: 64 }, (_, i) => digest(i, 16));
    const acc = new ByteAccumulator(64 * 16);
    const first = acc.subarray();
    runs.forEach((run) => acc.push(run));
    expect(acc.subarray().buffer, 'grew despite an exact hint').to.equal(first.buffer);
  });

  it('grows past an under-estimate without losing bytes', () => {
    const runs = Array.from({ length: 64 }, (_, i) => digest(i, 16));
    const acc = new ByteAccumulator(16);
    runs.forEach((run) => acc.push(run));
    expect(acc.subarray()).to.deep.equal(concatenate(runs));
  });

  it('accepts a run larger than the whole current capacity', () => {
    const acc = new ByteAccumulator(1);
    const big = digest(7, 5000);
    acc.push(digest(1, 3));
    acc.push(big);
    expect(acc.length).to.equal(5003);
    expect(acc.subarray().subarray(3)).to.deep.equal(big);
  });

  it('ignores empty pushes', () => {
    const acc = new ByteAccumulator();
    acc.push(new Uint8Array(0));
    acc.push(digest(2, 4));
    acc.push(new Uint8Array(0));
    expect(acc.subarray()).to.deep.equal(digest(2, 4));
  });

  it('copies out of the source, so later mutation of it does not leak in', () => {
    const acc = new ByteAccumulator(4);
    const run = digest(3, 4);
    acc.push(run);
    const before = Uint8Array.from(acc.subarray());
    run.fill(0xff);
    expect(acc.subarray()).to.deep.equal(before);
  });

  it('never exposes the unused tail of an over-estimated buffer', () => {
    const acc = new ByteAccumulator(1024);
    acc.push(digest(5, 10));
    expect(acc.subarray()).to.have.lengthOf(10);
  });
});
