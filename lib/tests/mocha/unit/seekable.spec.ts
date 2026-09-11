import { expect } from 'chai';
import { createSandbox, SinonSandbox } from 'sinon';

import { ConfigurationError } from '../../../src/errors.js';
import {
  bufferStream,
  type Chunker,
  fromSource,
  MAX_BUFFERED_STREAM_BYTES,
  sourceSize,
  sourceToStream,
  STREAM_CHUNK_SIZE,
} from '../../../src/seekable.js';

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

describe('sourceSize', () => {
  it('reads a buffer length without touching the data', async () => {
    expect(await sourceSize({ type: 'buffer', location: new Uint8Array(range(256)) })).to.equal(
      256
    );
  });

  it('reads a File/Blob size', async () => {
    const file = new Blob([new Uint8Array(range(256))]);
    expect(await sourceSize({ type: 'file-browser', location: file })).to.equal(256);
  });

  it('is undefined for sources whose size is unknowable up front', async () => {
    const { fromBuffer } = await import('../../../src/seekable.js');
    const readableStream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.close();
      },
    });
    expect(await sourceSize({ type: 'stream', location: readableStream })).to.be.undefined;
    expect(await sourceSize({ type: 'chunker', location: fromBuffer(new Uint8Array(4)) })).to.be
      .undefined;
  });

  describe('remote', () => {
    const url = 'http://localhost:3000/file';

    it('prefers HEAD Content-Length', async () => {
      const fetchSpy = box.spy(globalThis, 'fetch');
      expect(await sourceSize({ type: 'remote', location: url })).to.equal(256);
      expect(fetchSpy.callCount, 'HEAD alone should answer').to.equal(1);
      expect(fetchSpy.firstCall.args[1]?.method).to.equal('HEAD');
    });

    it('falls back to a one-byte range probe when HEAD is unusable', async () => {
      const real = globalThis.fetch;
      box
        .stub(globalThis, 'fetch')
        .callsFake(async (input: RequestInfo | URL, init?: RequestInit) => {
          if (init?.method === 'HEAD') {
            return new Response(null, { status: 405 });
          }
          return real(input, init);
        });
      expect(await sourceSize({ type: 'remote', location: url })).to.equal(256);
    });

    // A size probe is an optimization; it must never be able to fail an
    // otherwise valid encrypt.
    it('reports unknown rather than throwing when both probes fail', async () => {
      box.stub(globalThis, 'fetch').rejects(new TypeError('network down'));
      expect(await sourceSize({ type: 'remote', location: url })).to.be.undefined;
    });

    it('reports unknown when the server declines to say', async () => {
      box
        .stub(globalThis, 'fetch')
        .callsFake(async (_input: RequestInfo | URL, init?: RequestInit) =>
          init?.method === 'HEAD'
            ? new Response(null, { status: 405 })
            : new Response(new Uint8Array(1), {
                status: 206,
                headers: { 'Content-Range': 'bytes 0-0/*' },
              })
        );
      expect(await sourceSize({ type: 'remote', location: url })).to.be.undefined;
    });
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

  describe('remote', () => {
    const url = 'http://localhost:3000/file';

    it('should return a ReadableStream for remote source', async () => {
      const stream = await sourceToStream({ type: 'remote', location: url });
      expect(stream).to.be.an.instanceOf(ReadableStream);
      expect(await saveToBuffer(stream)).to.deep.equal(new Uint8Array(range(256)));
    });

    // The bug this replaces: the `default:` branch issued one unranged GET,
    // which buffers the entire object no matter how large it is.
    it('pulls a large object in bounded ranges rather than one GET', async () => {
      const total = 2 * STREAM_CHUNK_SIZE + 1024;
      const ranges: string[] = [];
      box.stub(globalThis, 'fetch').callsFake(async (_input, init?: RequestInit) => {
        if (init?.method === 'HEAD') {
          return new Response(null, { status: 200, headers: { 'Content-Length': `${total}` } });
        }
        const header = (init?.headers as Record<string, string> | undefined)?.Range;
        if (!header) {
          throw new Error('unranged GET issued for a remote source');
        }
        ranges.push(header);
        const [start, end] = header.replace('bytes=', '').split('-').map(Number);
        return new Response(new Uint8Array(end - start + 1), { status: 206 });
      });

      const stream = await sourceToStream({ type: 'remote', location: url });
      expect((await saveToBuffer(stream)).length).to.equal(total);
      expect(ranges).to.deep.equal([
        `bytes=0-${STREAM_CHUNK_SIZE - 1}`,
        `bytes=${STREAM_CHUNK_SIZE}-${2 * STREAM_CHUNK_SIZE - 1}`,
        `bytes=${2 * STREAM_CHUNK_SIZE}-${total - 1}`,
      ]);
    });

    // The last range stops exactly at the end. Reading past it would be a 416,
    // turning a clean finish into a thrown error.
    it('never requests a range past the end of the object', async () => {
      const fetchSpy = box.spy(globalThis, 'fetch');
      await saveToBuffer(await sourceToStream({ type: 'remote', location: url }));
      const rangeHeaders = fetchSpy
        .getCalls()
        .map((call) => (call.args[1]?.headers as Record<string, string> | undefined)?.Range)
        .filter(Boolean);
      expect(rangeHeaders).to.deep.equal(['bytes=0-255']);
    });

    it('reuses a size the caller already probed instead of probing again', async () => {
      const fetchSpy = box.spy(globalThis, 'fetch');
      const stream = await sourceToStream({ type: 'remote', location: url }, 256);
      expect(await saveToBuffer(stream)).to.deep.equal(new Uint8Array(range(256)));
      expect(fetchSpy.getCalls().map((call) => call.args[1]?.method)).to.not.include('HEAD');
    });

    // Without a length there is no way to know where to stop, so this keeps the
    // historical single-GET behaviour rather than walking into a 416.
    it('falls back to one unranged GET when the size is unknowable', async () => {
      const real = globalThis.fetch;
      const ranged: string[] = [];
      box.stub(globalThis, 'fetch').callsFake(async (input, init?: RequestInit) => {
        if (init?.method === 'HEAD') {
          return new Response(null, { status: 405 });
        }
        const header = (init?.headers as Record<string, string> | undefined)?.Range;
        if (header === 'bytes=0-0') {
          // The size probe's fallback: answer without disclosing a total.
          return new Response(new Uint8Array(1), {
            status: 206,
            headers: { 'Content-Range': 'bytes 0-0/*' },
          });
        }
        if (header) {
          ranged.push(header);
        }
        return real(input, init);
      });

      const stream = await sourceToStream({ type: 'remote', location: url });
      expect(await saveToBuffer(stream)).to.deep.equal(new Uint8Array(range(256)));
      expect(ranged, 'should not have attempted a ranged read').to.be.empty;
    });

    it('errors rather than truncating when a read comes back short', async () => {
      box.stub(globalThis, 'fetch').callsFake(async (_input, init?: RequestInit) => {
        if (init?.method === 'HEAD') {
          return new Response(null, { status: 200, headers: { 'Content-Length': '256' } });
        }
        return new Response(new Uint8Array(0), { status: 206 });
      });

      let error: Error | undefined;
      try {
        await saveToBuffer(await sourceToStream({ type: 'remote', location: url }));
      } catch (e) {
        error = e;
      }
      expect(error?.message).to.contain('truncated');
    });
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

describe('bufferStream', () => {
  /** A stream of `count` runs of `size` bytes, reporting how far it was read. */
  function runs(count: number, size: number) {
    const counter = { pulls: 0 };
    let emitted = 0;
    const stream = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          counter.pulls += 1;
          if (emitted >= count) {
            controller.close();
            return;
          }
          controller.enqueue(new Uint8Array(size).fill(emitted % 256));
          emitted += 1;
        },
      },
      { highWaterMark: 0 }
    );
    return { stream, counter };
  }

  it('joins the chunks in order', async () => {
    const { stream } = runs(4, 8);
    const buffered = await bufferStream(stream);
    expect(buffered.length).to.equal(32);
    expect([...buffered.subarray(0, 9)]).to.deep.equal([0, 0, 0, 0, 0, 0, 0, 0, 1]);
  });

  it('handles an empty stream', async () => {
    const { stream } = runs(0, 8);
    expect((await bufferStream(stream)).length).to.equal(0);
  });

  it('admits a stream exactly at the limit', async () => {
    const { stream } = runs(4, 8);
    expect((await bufferStream(stream, 32)).length).to.equal(32);
  });

  // The point of counting as we go rather than calling `Response.arrayBuffer()`:
  // a 50 GB stream should cost the limit, not 50 GB.
  it('refuses past the limit without draining the rest', async () => {
    const { stream, counter } = runs(100, 8);
    let error: Error | undefined;
    try {
      await bufferStream(stream, 32);
    } catch (e) {
      error = e;
    }
    expect(error).to.be.instanceOf(ConfigurationError);
    expect(error?.message).to.contain('too large to make seekable');
    expect(error?.message, 'should name the alternatives').to.contain('chunker');
    expect(counter.pulls, 'kept reading past the limit').to.equal(5);
  });

  it('defaults to a limit under the browser ArrayBuffer wall it exists to beat', () => {
    expect(MAX_BUFFERED_STREAM_BYTES).to.equal(1024 * 1024 * 1024);
    expect(MAX_BUFFERED_STREAM_BYTES).to.be.below(2 ** 31);
  });

  // The decrypt path: `fromSource` has to make a stream seekable, and this is
  // where the cost shows up. Re-enqueuing one buffer keeps the test's own
  // footprint at a megabyte while the accounting sees a gigabyte go by.
  it('bounds a stream decrypt source at the default limit', async () => {
    const shared = new Uint8Array(1024 * 1024);
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(shared);
      },
    });

    let error: Error | undefined;
    try {
      await fromSource({ type: 'stream', location: stream });
    } catch (e) {
      error = e;
    }
    expect(error).to.be.instanceOf(ConfigurationError);
    expect(error?.message).to.contain('too large to make seekable');
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
