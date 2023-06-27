import { expect } from 'chai';
import { createSandbox, SinonSandbox } from 'sinon';

import { type Chunker } from '../../../tdf3/src/utils/chunkers.js';


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

let box: SinonSandbox;
beforeEach(() => {
  box = createSandbox();
});
afterEach(() => {
  box.restore();
});

describe('chunkers', () => {
  describe('fromBuffer', () => {
    const r = range(256);
    const b = new Uint8Array(r);
    it('all', async () => {
      const { fromBuffer } = await import('../../../tdf3/src/utils/chunkers.js');
      const all = await fromBuffer(b)();
      expect(all).to.deep.equal(b);
      expect(Array.from(all)).to.deep.equal(r);
    });
    it('one', async () => {
      const { fromBuffer } = await import('../../../tdf3/src/utils/chunkers.js');
      const one = await fromBuffer(b)(1, 2);

      expect(one).to.deep.equal(b.slice(1, 2));
      expect(Array.from(one)).to.deep.equal([1]);
    });
    it('negative one', async () => {
      const { fromBuffer } = await import('../../../tdf3/src/utils/chunkers.js');
      const twofiftyfive = await fromBuffer(b)(-1);
      expect(twofiftyfive).to.deep.equal(b.slice(255));
      expect(Array.from(twofiftyfive)).to.deep.equal([255]);
    });
    it('negative two', async () => {
      const { fromBuffer } = await import('../../../tdf3/src/utils/chunkers.js');
      const twofiftyfour = await fromBuffer(b)(-2);
      expect(twofiftyfour).to.deep.equal(b.slice(254));
      expect(Array.from(twofiftyfour)).to.deep.equal([254, 255]);
    });
    it('negative three to negative 2', async () => {
      const { fromBuffer } = await import('../../../tdf3/src/utils/chunkers.js');
      const twofiftyfour = await fromBuffer(b)(-3, -2);
      expect(twofiftyfour).to.deep.equal(b.slice(253, 254));
      expect(Array.from(twofiftyfour)).to.deep.equal([253]);
    });
  });

  describe('fromUrl', () => {
    const r = range(256);
    const b = new Uint8Array(r);
    it('all', async () => {
      const { fromUrl } = await import('../../../tdf3/src/utils/chunkers.js');
      const c: Chunker = await fromUrl('http://localhost:3000/file');
      const all: Uint8Array = await c();
      console.log('all')
      console.log(all)
      console.log('b')
      console.log(b)
      console.log('Array.from(all)')
      console.log(Array.from(all))
      console.log('r')
      console.log(r)
      // expect(all).to.deep.equal(b);
      // expect(Array.from(all)).to.deep.equal(r);
    });
    // it('one', async () => {
    //   const { fromUrl } = await import('../../../tdf3/src/utils/chunkers.js');
    //   const c: Chunker = await fromUrl('http://localhost:3000/file');
    //   const one: Uint8Array = await c(1, 2);
    //   expect(one).to.deep.equal(b.slice(1, 2));
    //   expect(Array.from(one)).to.deep.eq([1]);
    // });
    // it('negative one', async () => {
    //   const { fromUrl } = await import('../../../tdf3/src/utils/chunkers.js');
    //   const twofiftyfive: Uint8Array = await (await fromUrl('http://localhost:3000/file'))(-1);
    //   expect(twofiftyfive).to.deep.equal(b.slice(255));
    //   expect(Array.from(twofiftyfive)).to.deep.equal([255]);
    // });
    // it('negative two', async () => {
    //   const { fromUrl } = await import('../../../tdf3/src/utils/chunkers.js');
    //   try {
    //     await (
    //       await fromUrl('http://localhost:3000/file')
    //     )(-2, -1);
    //     expect.fail();
    //   } catch (e) {
    //     expect(e).to.be.an('error');
    //   }
    // });
    // it('unsatisiable', async () => {
    //   const { fromUrl } = await import('../../../tdf3/src/utils/chunkers.js');
    //   try {
    //     await (
    //       await fromUrl('http://localhost:3000/file')
    //     )(12, 5);
    //     expect.fail();
    //   } catch (e) {
    //     expect(e.message).to.include('416');
    //   }
    // });
    // it('broken stream all', async () => {
    //   const { fromUrl } = await import('../../../tdf3/src/utils/chunkers.js');
    //   try {
    //     const c: Chunker = await fromUrl('http://localhost:3000/error');
    //     await c();
    //     expect.fail();
    //   } catch (e) {
    //     expect(e.message).to.include('404');
    //   }
    // });
    // it('broken stream some', async () => {
    //   const { fromUrl } = await import('../../../tdf3/src/utils/chunkers.js');
    //   try {
    //     const c: Chunker = await fromUrl('http://localhost:3000/error');
    //     await c(1);
    //     expect.fail();
    //   } catch (e) {
    //     expect(e.message).to.include('404');
    //   }
    // });
  });
});
