import { expect } from '@esm-bundle/chai';
import { openAsBlob } from 'node:fs';
import { mkdtemp, open, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fromSource, sourceToStream } from '@opentdf/sdk';
import { type FileChunker, openFileChunker, resolveRange } from '../src/file-chunker.js';

const text = (u: Uint8Array) => new TextDecoder().decode(u);

describe('resolveRange', function () {
  it('matches Uint8Array.slice semantics', function () {
    const a = new Uint8Array(10).map((_, i) => i);
    const cases: [number | undefined, number | undefined][] = [
      [undefined, undefined],
      [0, undefined],
      [3, undefined],
      [3, 7],
      [-4, undefined],
      [-4, -1],
      [-100, undefined],
      [7, 3],
      [0, 100],
      [10, 18],
      [12, undefined],
    ];
    for (const [s, e] of cases) {
      const [start, end] = resolveRange(a.length, s, e);
      expect(Array.from(a.subarray(start, end)), `[${s}, ${e})`).to.deep.equal(
        Array.from(a.slice(s, e))
      );
    }
  });
});

describe('openFileChunker', function () {
  let dir: string;
  const opened: FileChunker[] = [];
  before(async function () {
    dir = await mkdtemp(join(tmpdir(), 'file-chunker-'));
  });
  afterEach(async function () {
    await Promise.all(opened.splice(0).map((c) => c.close()));
  });
  after(async function () {
    await rm(dir, { recursive: true, force: true });
  });
  const openTracked = async (p: string) => {
    const c = await openFileChunker(p);
    opened.push(c);
    return c;
  };

  it('reads ranges, negative offsets, and the whole file', async function () {
    const p = join(dir, 'small.txt');
    await writeFile(p, 'hello, world');
    const c = await openTracked(p);
    expect(c.size).to.equal(12);
    expect(text(await c())).to.equal('hello, world');
    expect(text(await c(0, 5))).to.equal('hello');
    expect(text(await c(7))).to.equal('world');
    expect(text(await c(-5))).to.equal('world');
    expect(text(await c(-1000))).to.equal('hello, world');
    expect((await c(12, 20)).length).to.equal(0);
  });

  it('streams the whole file through sourceToStream (encrypt path)', async function () {
    const p = join(dir, 'stream.bin');
    const data = new Uint8Array(20 * 1024 * 1024 + 3).map((_, i) => i & 0xff);
    await writeFile(p, data);
    const c = await openTracked(p);
    const stream = await sourceToStream({ type: 'chunker', location: c });
    const got = new Uint8Array(await new Response(stream).arrayBuffer());
    expect(got.length).to.equal(data.length);
    expect(got.subarray(-3)).to.deep.equal(data.subarray(-3));
  });

  it('rejects a file rewritten between reads', async function () {
    const p = join(dir, 'rewritten.txt');
    await writeFile(p, 'AAAABBBB');
    const c = await openTracked(p);
    expect(text(await c(0, 4))).to.equal('AAAA');

    await writeFile(p, 'CCCCDDDD');
    let err: unknown;
    try {
      await c(4, 8);
    } catch (e) {
      err = e;
    }
    expect(err).to.be.instanceOf(Error);
    expect((err as Error).message).to.include('file changed while reading');
  });

  it('rejects a truncated file instead of ending the encrypt stream early', async function () {
    const p = join(dir, 'truncated.txt');
    await writeFile(p, 'AAAABBBB');
    const c = await openTracked(p);
    await writeFile(p, 'AAAA');

    const stream = await sourceToStream({ type: 'chunker', location: c });
    let err: unknown;
    try {
      await new Response(stream).arrayBuffer();
    } catch (e) {
      err = e;
    }
    expect(err).to.be.instanceOf(Error);
    expect((err as Error).message).to.include('file changed while reading');
  });

  it('rejects reads after close, and close is idempotent', async function () {
    const p = join(dir, 'closed.txt');
    await writeFile(p, 'x');
    const c = await openFileChunker(p);
    await c.close();
    await c.close();
    let err: unknown;
    try {
      await c(0, 1);
    } catch (e) {
      err = e;
    }
    expect(err).to.be.instanceOf(Error);
  });

  it('fails to open a missing file or a directory', async function () {
    for (const p of [join(dir, 'nope'), dir]) {
      let err: unknown;
      try {
        opened.push(await openFileChunker(p));
      } catch (e) {
        err = e;
      }
      expect(err, p).to.be.instanceOf(Error);
    }
  });

  // DSPX-5160: a sparse file just over 4 GiB, with a known tail. Occupies only
  // a few KiB on disk on filesystems that support sparse files (APFS, ext4).
  describe('files of 4 GiB or more', function () {
    const SIZE = 2 ** 32 + 4096;
    const TAIL = 'PK\x05\x06-tail-marker';
    let big: string;
    before(async function () {
      big = join(dir, 'sparse-4g.bin');
      const fh = await open(big, 'w');
      try {
        await fh.truncate(SIZE);
        await fh.write(TAIL, SIZE - TAIL.length, 'latin1');
      } finally {
        await fh.close();
      }
    });

    it('reports the real size', async function () {
      const c = await openTracked(big);
      expect(c.size).to.equal(SIZE);
    });

    it('reads the tail with a negative offset', async function () {
      const c = await openTracked(big);
      expect(text(await c(-TAIL.length))).to.equal(TAIL);
      expect(text(await c(-1000)).endsWith(TAIL)).to.be.true;
    });

    it('reads an explicit range above 2^32', async function () {
      const c = await openTracked(big);
      expect(text(await c(SIZE - TAIL.length, SIZE))).to.equal(TAIL);
      expect(text(await c(SIZE - TAIL.length, SIZE - TAIL.length + 2))).to.equal('PK');
    });

    // Documents the Node behaviour this module works around. If this starts
    // failing, Node has fixed nodejs/node#66207 (and the matching slice()
    // CHECK), and openAsBlob may be usable again for large files.
    it('openAsBlob still truncates size to 32 bits (nodejs/node#66207)', async function () {
      const blob = await openAsBlob(big);
      expect(blob.size).to.equal(SIZE % 2 ** 32);
      // ...so the SDK's file-browser source reads the "tail" from the wrong place.
      const viaBlob = await fromSource({ type: 'file-browser', location: blob });
      expect(text(await viaBlob(-TAIL.length))).not.to.equal(TAIL);
    });
  });
});
