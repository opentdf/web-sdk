import { expect } from 'chai';
import fs from 'node:fs';
import { createSandbox, SinonSandbox } from 'sinon';
import { createServer, Server } from 'node:http';
import send from 'send';
import { type Chunker } from '../../src/utils/chunkers.js';
import { type AddressInfo } from 'node:net';
import type EventEmitter from 'node:events';
import { promisify } from 'node:util';

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

describe('chunkers', () => {
  describe('fromBuffer', () => {
    const r = range(256);
    const b = new Uint8Array(r);
    it('all', async () => {
      const { fromBuffer } = await import('../../src/utils/chunkers.js');
      const all = await fromBuffer(b)();
      expect(all).to.deep.equal(b);
      expect(Array.from(all)).to.deep.equal(r);
    });
    it('one', async () => {
      const { fromBuffer } = await import('../../src/utils/chunkers.js');
      const one = await fromBuffer(b)(1, 2);
      expect(one).to.deep.equal(b.slice(1, 2));
      expect(Array.from(one)).to.deep.equal([1]);
    });
    it('negative one', async () => {
      const { fromBuffer } = await import('../../src/utils/chunkers.js');
      const twofiftyfive = await fromBuffer(b)(-1);
      expect(twofiftyfive).to.deep.equal(b.slice(255));
      expect(Array.from(twofiftyfive)).to.deep.equal([255]);
    });
    it('negative two', async () => {
      const { fromBuffer } = await import('../../src/utils/chunkers.js');
      const twofiftyfour = await fromBuffer(b)(-2);
      expect(twofiftyfour).to.deep.equal(b.slice(254));
      expect(Array.from(twofiftyfour)).to.deep.equal([254, 255]);
    });
    it('negative three to negative 2', async () => {
      const { fromBuffer } = await import('../../src/utils/chunkers.js');
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
    beforeEach(() => {
      const statSyncOriginal = fs.statSync;
      // @ts-ignore
      box.stub(fs, 'statSync').callsFake((p: string) => {
        switch (p) {
          case 'file://local/file':
          case 'file://fails':
            return { size: 256 };
          case 'file://not/found':
            throw new Error('File not found');
          default:
            return statSyncOriginal(path);
        }
      });

      const readFileOriginal = fs.readFile;
      box
        .stub(fs, 'readFile') // @ts-ignore
        .callsFake((p: string, f: (err?: unknown, data?: Buffer) => void) => {
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
              readFileOriginal(path, f);
          }
        });

      const createReadStreamOriginal = fs.createReadStream;
      // @ts-ignore
      box.stub(fs, 'createReadStream').callsFake((p: string, rg?: ByteRange) => {
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
                    // @ts-ignore
                    f(Buffer.from(range(start, end)));
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
            createReadStreamOriginal(path, rg);
        }
      });
    });
    it('all', async () => {
      const { fromNodeFile } = await import('../../src/utils/chunkers.js');
      const c: Chunker = fromNodeFile(path);
      const all: Uint8Array = await c();
      expect(all).to.deep.equal(b);
      expect(Array.from(all)).to.deep.equal(r);
    });
    it('one', async () => {
      const { fromNodeFile } = await import('../../src/utils/chunkers.js');
      const c: Chunker = fromNodeFile(path);
      const one: Uint8Array = await c(1, 2);
      expect(one).to.deep.equal(b.slice(1, 2));
      expect(Array.from(one)).to.deep.equal([1]);
    });
    it('negative one', async () => {
      const { fromNodeFile } = await import('../../src/utils/chunkers.js');
      const twofiftyfive: Uint8Array = await fromNodeFile(path)(-1);
      expect(twofiftyfive).to.deep.equal(b.slice(255));
      expect(Array.from(twofiftyfive)).to.deep.equal([255]);
    });
    it('negative two', async () => {
      const { fromNodeFile } = await import('../../src/utils/chunkers.js');
      const twofiftyfour: Uint8Array = await fromNodeFile(path)(-2, -1);
      expect(twofiftyfour).to.deep.equal(b.slice(254, 255));
      expect(Array.from(twofiftyfour)).to.deep.equal([254]);
    });
    it('missing', async () => {
      const { fromNodeFile } = await import('../../src/utils/chunkers.js');
      try {
        const c: Chunker = fromNodeFile('file://not/found');
        await c();
        expect.fail();
      } catch (e) {
        expect(e).to.be.an('error');
      }
    });
    it('broken stream all', async () => {
      const { fromNodeFile } = await import('../../src/utils/chunkers.js');
      try {
        const c: Chunker = fromNodeFile('file://fails');
        await c();
        expect.fail();
      } catch (e) {
        expect(e).to.be.an('error');
      }
    });
    it('broken stream some', async () => {
      const { fromNodeFile } = await import('../../src/utils/chunkers.js');
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
    const __dirname = new URL('.', import.meta.url).pathname;
    const baseDir = `${__dirname}/temp/artifacts`;
    const path = 'testfile.bin';
    const testFile = `${baseDir}/${path}`;
    const r = range(256);
    const b = new Uint8Array(r);
    let server: Server;
    before(async function startServer() {
      console.error('mkdir time');
      await fs.promises.mkdir(baseDir, { recursive: true });
      fs.writeFileSync(testFile, b);
      // response to all requests with this tdf file
      console.error('createServer time');
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
      console.error('server listening');
    });
    after(async function closeServer() {
      console.error('closeServer');
      return promisify((callback) => {
        console.error('time to server.close');
        server.close((err) => {
          console.error('server unref');
          server.unref();
          if (err) {
            console.error(err);
          }
          console.error('server callback time');
          callback(err, undefined);
        });
      });
    });

    const urlFor = (p: string) => `http://localhost:${(server.address() as AddressInfo).port}/${p}`;
    it('all', async () => {
      const { fromUrl } = await import('../../src/utils/chunkers.js');
      const c: Chunker = fromUrl(urlFor(path));
      const all: Uint8Array = await c();
      expect(all).to.deep.equal(b);
      expect(Array.from(all)).to.deep.equal(r);
    });
    it('one', async () => {
      const { fromUrl } = await import('../../src/utils/chunkers.js');
      const c: Chunker = fromUrl(urlFor(path));
      const one: Uint8Array = await c(1, 2);
      expect(one).to.deep.equal(b.slice(1, 2));
      expect(Array.from(one)).to.deep.eq([1]);
    });
    it('negative one', async () => {
      const { fromUrl } = await import('../../src/utils/chunkers.js');
      const twofiftyfive: Uint8Array = await fromUrl(urlFor(path))(-1);
      expect(twofiftyfive).to.deep.equal(b.slice(255));
      expect(Array.from(twofiftyfive)).to.deep.equal([255]);
    });
    it('negative two', async () => {
      const { fromUrl } = await import('../../src/utils/chunkers.js');
      try {
        await fromUrl(urlFor(path))(-2, -1);
        expect.fail();
      } catch (e) {
        expect(e).to.be.an('error');
      }
    });
    it('unsatisiable', async () => {
      const { fromUrl } = await import('../../src/utils/chunkers.js');
      try {
        await fromUrl(urlFor(path))(12, 5);
        expect.fail();
      } catch (e) {
        expect(e.message).to.include('416');
      }
    });
    it('broken stream all', async () => {
      const { fromUrl } = await import('../../src/utils/chunkers.js');
      try {
        const c: Chunker = fromUrl(urlFor('error'));
        await c();
        expect.fail();
      } catch (e) {
        expect(e.message).to.include('404');
      }
    });
    it('broken stream some', async () => {
      const { fromUrl } = await import('../../src/utils/chunkers.js');
      try {
        const c: Chunker = fromUrl(urlFor('error'));
        await c(1);
        expect.fail();
      } catch (e) {
        expect(e.message).to.include('404');
      }
    });
  });
});
