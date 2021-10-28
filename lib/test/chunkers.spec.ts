import { expect } from '@esm-bundle/chai';
import { fromBrowserFile } from '../src/chunkers';

function range(a: number, b?: number): number[] {
  if (!b) {
    return [...Array(a).keys()];
  }
  const l = b - a;
  const r = new Array(l);
  for (let i = 0; i < l; i += 1) {
    r[i] = a + i;
  }
  return r;
}

describe('chunkers', () => {
  describe('fromBrowserFile', () => {
    const r = range(256);
    const b = new Uint8Array(r);
    it('all', async () => {
      const blob = new Blob([b.buffer]);
      const all = await fromBrowserFile(blob)();
      expect(Array.from(all)).to.eql(r);
      expect(all).to.eql(b);
    });
    it('one', async () => {
      const blob = new Blob([b.buffer]);
      const one = await fromBrowserFile(blob)(1, 2);
      expect(one).to.eql(b.slice(1, 2));
      expect(Array.from(one)).to.eql([1]);
    });
    it('negative one', async () => {
      const blob = new Blob([b.buffer]);
      const twofiftyfive = await fromBrowserFile(blob)(-1);
      expect(twofiftyfive).to.eql(b.slice(255));
      expect(Array.from(twofiftyfive)).to.eql([255]);
    });
    it('negative two', async () => {
      const blob = new Blob([b.buffer]);
      const twofiftyfour = await fromBrowserFile(blob)(-2);
      expect(twofiftyfour).to.eql(b.slice(254));
      expect(Array.from(twofiftyfour)).to.eql([254, 255]);
    });
    it('negative three to negative 2', async () => {
      const blob = new Blob([b.buffer]);
      const twofiftyfour = await fromBrowserFile(blob)(-3, -2);
      expect(twofiftyfour).to.eql(b.slice(253, 254));
      expect(Array.from(twofiftyfour)).to.eql([253]);
    });
  });
});
