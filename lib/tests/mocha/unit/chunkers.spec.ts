import { expect } from 'chai';
import esmock from 'esmock';
import type EventEmitter from 'node:events';
import fs from 'node:fs';
import { createServer, Server } from 'node:http';
import send from 'send';
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

type ByteRange = {
  start?: number;
  end?: number;
};

function sourceDirectory() {
  try {
    if (__dirname) {
      return __dirname;
    }
  } catch (e) {
    // this is expected to throw in import (ESM) code
  }
  return new URL('.', import.meta?.url).pathname;
}

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

  // path: PathLike, options?: StatSyncOptions | undefined) => Stats | BigIntStats | undefined'
  describe('fromNodeFile', () => {
    const r = range(256);
    const b = new Uint8Array(r);
    const path = 'file://local/file';
    const mocks = {
      fs: {
        statSync: (p: string) => {
          switch (p) {
            case 'file://local/file':
            case 'file://fails':
              return { size: 256 };
            case 'file://not/found':
              throw new Error('File not found');
            default:
              return fs.statSync(path);
          }
        },
        readFile: (p: string, f: (err?: unknown, data?: Buffer) => void) => {
          switch (p) {
            case 'file://local/file':
              f(undefined, Buffer.from(range(256)));
              break;
            case 'file://fails':
              f(new Error('I/O Error'), undefined);
              break;
            case 'file://not/found':
              f(new Error('File not found'), undefined);
              break;
            default:
              fs.readFile(path, f);
          }
        },
        createReadStream: (p: string, rg?: ByteRange) => {
          let { start, end } = rg || { start: undefined, end: undefined };
          switch (p) {
            case 'file://local/file':
              if (!start && start !== 0) {
                start = 0;
              }
              if (!end) {
                end = 256;
              } else {
                // createReadStream end is inclusive
                end += 1;
              }
              return {
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                on: (e: string, f: (...args: any[]) => void) => {
                  switch (e) {
                    case 'data':
                      f(Buffer.from(range(start || 0, end)));
                      return this;
                    case 'end':
                      f();
                      return this;
                    case 'error':
                      return this;
                    default:
                      throw new Error();
                  }
                },
              };
            case 'file://fails':
              return {
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                on: (e: string, f: (...args: any[]) => void) => {
                  switch (e) {
                    case 'data':
                      return this;
                    case 'end':
                      return this;
                    case 'error':
                      f(new Error('I/O Error'));
                      return this;
                    default:
                      throw new Error();
                  }
                },
              };
            case 'file://not/found':
              throw new Error('File not found');
            default:
              return fs.createReadStream(path, rg);
          }
        },
      },
    };
    it('all', async () => {
      const { fromNodeFile } = await esmock('../../../tdf3/src/utils/chunkers.ts', mocks);
      const c: Chunker = fromNodeFile(path);
      const all: Uint8Array = await c();
      expect(all).to.deep.equal(b);
      expect(Array.from(all)).to.deep.equal(r);
    });
    it('one', async () => {
      const { fromNodeFile } = await esmock('../../../tdf3/src/utils/chunkers.ts', mocks);
      const c: Chunker = fromNodeFile(path);
      const one: Uint8Array = await c(1, 2);
      expect(one).to.deep.equal(b.slice(1, 2));
      expect(Array.from(one)).to.deep.equal([1]);
    });
    it('negative one', async () => {
      const { fromNodeFile } = await esmock('../../../tdf3/src/utils/chunkers.ts', mocks);
      const twofiftyfive: Uint8Array = await fromNodeFile(path)(-1);
      expect(twofiftyfive).to.deep.equal(b.slice(255));
      expect(Array.from(twofiftyfive)).to.deep.equal([255]);
    });
    it('negative two', async () => {
      const { fromNodeFile } = await esmock('../../../tdf3/src/utils/chunkers.ts', mocks);
      const twofiftyfour: Uint8Array = await fromNodeFile(path)(-2, -1);
      expect(twofiftyfour).to.deep.equal(b.slice(254, 255));
      expect(Array.from(twofiftyfour)).to.deep.equal([254]);
    });
    it('missing', async () => {
      const { fromNodeFile } = await esmock('../../../tdf3/src/utils/chunkers.ts', mocks);
      try {
        const c: Chunker = fromNodeFile('file://not/found');
        await c();
        expect.fail();
      } catch (e) {
        expect(e).to.be.an('error');
      }
    });
    it('broken stream all', async () => {
      const { fromNodeFile } = await esmock('../../../tdf3/src/utils/chunkers.ts', mocks);
      try {
        const c: Chunker = fromNodeFile('file://fails');
        await c();
        expect.fail();
      } catch (e) {
        expect(e).to.be.an('error');
      }
    });
    it('broken stream some', async () => {
      const { fromNodeFile } = await esmock('../../../tdf3/src/utils/chunkers.ts', mocks);
      try {
        const c: Chunker = fromNodeFile('file://fails');
        await c(1);
        expect.fail();
      } catch (e) {
        expect(e).to.be.an('error');
      }
    });
  });

  describe('fromUrl', () => {
    const baseDir = `${sourceDirectory()}/temp/artifacts`;
    const path = 'testfile.bin';
    const testFile = `${baseDir}/${path}`;
    const r = range(256);
    const b = new Uint8Array(r);
    let server: Server;
    before(async function startServer() {
      await fs.promises.mkdir(baseDir, { recursive: true });
      fs.writeFileSync(testFile, b);
      // response to all requests with this tdf file
      server = createServer((req, res) => {
        if (req.url?.endsWith('error')) {
          send(req, req.url)
            .on('stream', (stream: EventEmitter) => {
              stream.on('open', () => {
                stream.emit('error', new Error('Something 500-worthy'));
              });
            })
            .pipe(res);
        } else {
          send(req, `${baseDir}${req.url}`).pipe(res);
        }
      });
      server.listen();
    });
    after(function closeServer(done) {
      server.close((err) => {
        server.unref();
        done(err);
      });
    });
    const urlFor = (p: string) => {
      const address = server.address();
      if (typeof address === 'string') {
        return `${address}/${p}`;
      }
      return `http://localhost:${address?.port}/${p}`;
    };
    it('all', async () => {
      const { fromUrl } = await import('../../../tdf3/src/utils/chunkers.js');
      const c: Chunker = await fromUrl(urlFor(path));
      const all: Uint8Array = await c();
      expect(all).to.deep.equal(b);
      expect(Array.from(all)).to.deep.equal(r);
    });
    it('one', async () => {
      const { fromUrl } = await import('../../../tdf3/src/utils/chunkers.js');
      const c: Chunker = await fromUrl(urlFor(path));
      const one: Uint8Array = await c(1, 2);
      expect(one).to.deep.equal(b.slice(1, 2));
      expect(Array.from(one)).to.deep.eq([1]);
    });
    it('negative one', async () => {
      const { fromUrl } = await import('../../../tdf3/src/utils/chunkers.js');
      const twofiftyfive: Uint8Array = await (await fromUrl(urlFor(path)))(-1);
      expect(twofiftyfive).to.deep.equal(b.slice(255));
      expect(Array.from(twofiftyfive)).to.deep.equal([255]);
    });
    it('negative two', async () => {
      const { fromUrl } = await import('../../../tdf3/src/utils/chunkers.js');
      try {
        await (
          await fromUrl(urlFor(path))
        )(-2, -1);
        expect.fail();
      } catch (e) {
        expect(e).to.be.an('error');
      }
    });
    it('unsatisiable', async () => {
      const { fromUrl } = await import('../../../tdf3/src/utils/chunkers.js');
      try {
        await (
          await fromUrl(urlFor(path))
        )(12, 5);
        expect.fail();
      } catch (e) {
        expect(e.message).to.include('416');
      }
    });
    it('broken stream all', async () => {
      const { fromUrl } = await import('../../../tdf3/src/utils/chunkers.js');
      try {
        const c: Chunker = await fromUrl(urlFor('error'));
        await c();
        expect.fail();
      } catch (e) {
        expect(e.message).to.include('404');
      }
    });
    it('broken stream some', async () => {
      const { fromUrl } = await import('../../../tdf3/src/utils/chunkers.js');
      try {
        const c: Chunker = await fromUrl(urlFor('error'));
        await c(1);
        expect.fail();
      } catch (e) {
        expect(e.message).to.include('404');
      }
    });
  });
});
