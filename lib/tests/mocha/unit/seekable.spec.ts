import { expect } from 'chai';
import type { SinonSandbox } from 'sinon';
import { createSandbox } from 'sinon';

import { InvalidFileError } from '../../../src/errors.js';
import { type Chunker, fromSource, sourceToStream } from '../../../src/seekable.js';

function range(a: number, b?: number): number[] {
  if (!b) {
    return Array.from({ length: a }, (_, index) => index);
  }
  const l = b - a;
  const r: number[] = new Array<number>(l);
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

  describe('fromBrowserFile', () => {
    const b = new Uint8Array(range(256));
    /** Delegates to a real Blob, but is not one: like a Blob from another realm. */
    const blobLike = (blob: Blob): Blob =>
      ({
        size: blob.size,
        type: blob.type,
        slice: (start?: number, end?: number) => blobLike(blob.slice(start, end)),
        arrayBuffer: () => blob.arrayBuffer(),
      }) as Blob;

    for (const [name, wrap] of [
      ['Blob', (blob: Blob) => blob],
      ['Blob-like object', blobLike],
    ] as const) {
      it(`reads all, a range and a suffix of a ${name}`, async () => {
        const { fromBrowserFile } = await import('../../../src/seekable.js');
        const chunker = fromBrowserFile(wrap(new Blob([b])));
        expect(await chunker()).to.deep.equal(b);
        expect(Array.from(await chunker(1, 3))).to.deep.equal([1, 2]);
        expect(Array.from(await chunker(-2))).to.deep.equal([254, 255]);
      });
    }
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
    it('uses HEAD to bound later ranges when a suffix response omits Content-Range', async () => {
      const fetchStub = box.stub(globalThis, 'fetch').callsFake((_input, init) => {
        if (init?.method === 'HEAD') {
          return Promise.resolve(
            new Response(null, { status: 200, headers: { 'Content-Length': '1024' } })
          );
        }
        return Promise.resolve(new Response(new Uint8Array(1024), { status: 206 }));
      });
      const { fromUrl } = await import('../../../src/seekable.js');
      const chunker = await fromUrl('https://example.test/archive.tdf');
      await chunker(-1024);
      try {
        await chunker(1024, 1025);
        expect.fail('expected the out-of-bounds request to be rejected');
      } catch (e) {
        expect(e).to.be.instanceOf(InvalidFileError);
      }
      expect(fetchStub.callCount).to.equal(2);
      expect(fetchStub.secondCall.args[1]?.method).to.equal('HEAD');
    });
    it('accepts a range ending at the remote length and rejects one past it', async () => {
      const body = new Uint8Array(range(256));
      box.stub(globalThis, 'fetch').callsFake((_input, init) => {
        const header = new Headers(init?.headers).get('Range') ?? '';
        const [, from, to] = /^bytes=(-?\d*)-?(\d*)$/.exec(header) ?? [];
        const start = from.startsWith('-') ? body.length + Number(from) : Number(from);
        const end = to ? Number(to) + 1 : body.length;
        return Promise.resolve(
          new Response(body.slice(start, end), {
            status: 206,
            headers: { 'Content-Range': `bytes ${start}-${end - 1}/${body.length}` },
          })
        );
      });
      const { fromUrl } = await import('../../../src/seekable.js');
      const chunker = await fromUrl('https://example.test/archive.tdf');
      await chunker(-16);
      expect(await chunker(255, 256)).to.deep.equal(body.slice(255));
      try {
        await chunker(255, 257);
        expect.fail('expected the out-of-bounds request to be rejected');
      } catch (e) {
        expect(e).to.be.instanceOf(InvalidFileError);
      }
    });
    for (const [name, head] of [
      ['rejects HEAD', () => Promise.resolve(new Response(null, { status: 403 }))],
      ['omits Content-Length on HEAD', () => Promise.resolve(new Response(null, { status: 200 }))],
      ['fails HEAD at the network', () => Promise.reject(new TypeError('Failed to fetch'))],
    ] as const) {
      it(`continues without a length when the server ${name}`, async () => {
        const body = new Uint8Array(range(256));
        const fetchStub = box.stub(globalThis, 'fetch').callsFake((_input, init) => {
          if (init?.method === 'HEAD') {
            return head();
          }
          return Promise.resolve(new Response(body, { status: 206 }));
        });
        const { fromUrl } = await import('../../../src/seekable.js');
        const chunker = await fromUrl('https://example.test/archive.tdf');
        await chunker(-256);
        expect(await chunker(0, 256)).to.deep.equal(body);
        expect(await chunker(0, 256)).to.deep.equal(body);
        const methods = fetchStub.getCalls().map((c) => c.args[1]?.method ?? 'GET');
        expect(methods).to.deep.equal(['GET', 'HEAD', 'GET', 'GET']);
      });
    }
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
      // @ts-expect-error Deliberately verifies an unsupported source type.
      await fromSource({ type: 'unsupported', location: 'unsupported' });
      expect.fail();
    } catch (e) {
      expect(e).to.be.an('error');
      if (e instanceof Error) {
        expect(e.message).to.include('Data source type not defined, or not supported');
      }
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
