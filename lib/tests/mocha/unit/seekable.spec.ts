import { expect } from 'chai';
import { createSandbox, SinonSandbox } from 'sinon';

import { type Chunker, fromSource, sourceToStream } from '../../../src/seekable.js';

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
      const { fromBuffer } = await import('../../../src/seekable.js');
      const all = await fromBuffer(b)();
      expect(all).to.deep.equal(b);
      expect(Array.from(all)).to.deep.equal(r);
    });
    it('one', async () => {
      const { fromBuffer } = await import('../../../src/seekable.js');
      const one = await fromBuffer(b)(1, 2);
      expect(one).to.deep.equal(b.slice(1, 2));
      expect(Array.from(one)).to.deep.equal([1]);
    });
    it('negative one', async () => {
      const { fromBuffer } = await import('../../../src/seekable.js');
      const twofiftyfive = await fromBuffer(b)(-1);
      expect(twofiftyfive).to.deep.equal(b.slice(255));
      expect(Array.from(twofiftyfive)).to.deep.equal([255]);
    });
    it('negative two', async () => {
      const { fromBuffer } = await import('../../../src/seekable.js');
      const twofiftyfour = await fromBuffer(b)(-2);
      expect(twofiftyfour).to.deep.equal(b.slice(254));
      expect(Array.from(twofiftyfour)).to.deep.equal([254, 255]);
    });
    it('negative three to negative 2', async () => {
      const { fromBuffer } = await import('../../../src/seekable.js');
      const twofiftyfour = await fromBuffer(b)(-3, -2);
      expect(twofiftyfour).to.deep.equal(b.slice(253, 254));
      expect(Array.from(twofiftyfour)).to.deep.equal([253]);
    });
  });

  describe('fromUrl', () => {
    const r = range(256);
    const b = new Uint8Array(r);
    it('all', async () => {
      const { fromUrl } = await import('../../../src/seekable.js');
      const c: Chunker = await fromUrl('http://localhost:3000/file');
      const all: Uint8Array = new Uint8Array(await c());
      expect(all).to.deep.equal(b);
      expect(Array.from(all)).to.deep.equal(r);
    });
    it('one', async () => {
      const { fromUrl } = await import('../../../src/seekable.js');
      const c: Chunker = await fromUrl('http://localhost:3000/file');
      const one: Uint8Array = new Uint8Array(await c(1, 2));
      expect(one).to.deep.equal(b.slice(1, 2));
      expect(Array.from(one)).to.deep.eq([1]);
    });
    it('negative one', async () => {
      const { fromUrl } = await import('../../../src/seekable.js');
      const twofiftyfive: Uint8Array = new Uint8Array(
        await (
          await fromUrl('http://localhost:3000/file')
        )(-1)
      );
      expect(twofiftyfive).to.deep.equal(b.slice(255));
      expect(Array.from(twofiftyfive)).to.deep.equal([255]);
    });
    it('negative two', async () => {
      const { fromUrl } = await import('../../../src/seekable.js');
      try {
        await (
          await fromUrl('http://localhost:3000/file')
        )(-2, -1);
        expect.fail();
      } catch (e) {
        expect(e).to.be.an('error');
      }
    });
    it('unsatisiable', async () => {
      const { fromUrl } = await import('../../../src/seekable.js');
      try {
        await (
          await fromUrl('http://localhost:3000/file')
        )(12, 5);
        expect.fail();
      } catch (e) {
        expect(() => {
          throw e;
        }).to.throw('416');
      }
    });
    it('broken stream all', async () => {
      const { fromUrl } = await import('../../../src/seekable.js');
      try {
        const c: Chunker = await fromUrl('http://localhost:3000/error');
        await c();
        expect.fail();
      } catch (e) {
        expect(() => {
          throw e;
        }).to.throw('404');
      }
    });
    it('broken stream some', async () => {
      const { fromUrl } = await import('../../../src/seekable.js');
      try {
        const c: Chunker = await fromUrl('http://localhost:3000/error');
        await c(1);
        expect.fail();
      } catch (e) {
        expect(() => {
          throw e;
        }).to.throw('404');
      }
    });
  });
});

describe('fromSource', () => {
  it('should return a chunker for buffer source', async () => {
    const b = new Uint8Array(range(256));
    const chunker = await fromSource({ type: 'buffer', location: b });
    const result = await chunker();
    expect(result).to.deep.equal(b);
  });

  it('should return a chunker for chunker source', async () => {
    const b = new Uint8Array(range(256));
    const { fromBuffer } = await import('../../../src/seekable.js');
    const originalChunker = fromBuffer(b);
    const chunker = await fromSource({ type: 'chunker', location: originalChunker });
    const result = await chunker();
    expect(result).to.deep.equal(b);
  });

  it('should return a chunker for file-browser source', async () => {
    const file = new Blob([new Uint8Array(range(256))]);
    const chunker = await fromSource({ type: 'file-browser', location: file });
    const result = await chunker();
    expect(result).to.deep.equal(new Uint8Array(await file.arrayBuffer()));
  });

  it('should return a chunker for remote source', async () => {
    const chunker = await fromSource({ type: 'remote', location: 'http://localhost:3000/file' });
    const result = await chunker();
    expect(result).to.deep.equal(new Uint8Array(range(256)));
  });

  it('should return a chunker for stream source', async () => {
    const b = new Uint8Array(range(256));
    const readableStream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(b);
        controller.close();
      },
    });
    const chunker = await fromSource({ type: 'stream', location: readableStream });
    const result = await chunker();
    expect(result).to.deep.equal(b);
  });

  it('should throw an error for unsupported source type', async () => {
    try {
      await fromSource({ type: 'unsupported', location: 'unsupported' } as any);
      expect.fail();
    } catch (e) {
      expect(e).to.be.an('error');
      expect(e.message).to.include('Data source type not defined, or not supported');
    }
  });
});

describe('sourceToStream', () => {
  it('should return a ReadableStream for buffer source', async () => {
    const b = new Uint8Array(range(256));
    const stream = await sourceToStream({ type: 'buffer', location: b });
    expect(stream).to.be.an.instanceOf(ReadableStream);
  });

  it('should return a ReadableStream for file-browser source', async () => {
    const file = new Blob([new Uint8Array(range(256))]);
    const stream = await sourceToStream({ type: 'file-browser', location: file });
    expect(stream).to.be.an.instanceOf(ReadableStream);
  });

  it('should return a ReadableStream for chunker source', async () => {
    const { fromBuffer } = await import('../../../src/seekable.js');
    const b = new Uint8Array(range(256));
    const chunker = fromBuffer(b);
    const stream = await sourceToStream({ type: 'chunker', location: chunker });
    expect(stream).to.be.an.instanceOf(ReadableStream);
    const result = await saveToBuffer(stream);
    expect(result).to.deep.equal(b);
  });

  it('should return a ReadableStream for remote source', async () => {
    const stream = await sourceToStream({
      type: 'remote',
      location: 'http://localhost:3000/file',
    });
    expect(stream).to.be.an.instanceOf(ReadableStream);
  });

  it('should return a ReadableStream for stream source', async () => {
    const b = new Uint8Array(range(256));
    const readableStream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(b);
        controller.close();
      },
    });
    const stream = await sourceToStream({ type: 'stream', location: readableStream });
    expect(stream).to.be.an.instanceOf(ReadableStream);
    const result = await saveToBuffer(stream);
    expect(result).to.deep.equal(b);
  });

  it('should return a ReadableStream', async () => {
    const { fromBuffer } = await import('../../../src/seekable.js');
    const b = new Uint8Array(range(256));
    const chunker = fromBuffer(b);
    const stream = await sourceToStream({ type: 'chunker', location: chunker });
    expect(stream).to.be.an.instanceOf(ReadableStream);
    const result = await saveToBuffer(stream);
    expect(result).to.deep.equal(b);
  });
});

async function saveToBuffer(stream: ReadableStream<Uint8Array>) {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let done = false;

  while (!done) {
    const { value, done: readerDone } = await reader.read();
    if (value) {
      chunks.push(value);
    }
    done = readerDone;
  }

  const result = new Uint8Array(chunks.reduce((acc, chunk) => acc + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}
