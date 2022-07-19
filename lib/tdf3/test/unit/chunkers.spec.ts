import { expect } from 'chai';
import fs from 'fs';
import { createSandbox } from 'sinon';
import { createServer } from 'http';
// @ts-ignore
import send from 'send';
import { chunker, fromBuffer, fromNodeFile, fromUrl } from '../../src/utils/chunkers';

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
// @ts-ignore
let box;
beforeEach(() => {
  box = createSandbox();
});
afterEach(() => {
  // @ts-ignore
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
      const all = await fromBuffer(b)();
      // @ts-ignore
      expect(all).to.deep.eql(b);
      // @ts-ignore
      expect(Array.from(all)).to.deep.eql(r);
    });
    it('one', async () => {
      const one = await fromBuffer(b)(1, 2);
      // @ts-ignore
      expect(one).to.deep.eql(b.slice(1, 2));
      // @ts-ignore
      expect(Array.from(one)).to.deep.eql([1]);
    });
    it('negative one', async () => {
      const twofiftyfive = await fromBuffer(b)(-1);
      // @ts-ignore
      expect(twofiftyfive).to.deep.eql(b.slice(255));
      // @ts-ignore
      expect(Array.from(twofiftyfive)).to.deep.eql([255]);
    });
    it('negative two', async () => {
      const twofiftyfour = await fromBuffer(b)(-2);
      // @ts-ignore
      expect(twofiftyfour).to.deep.eql(b.slice(254));
      // @ts-ignore
      expect(Array.from(twofiftyfour)).to.deep.eql([254, 255]);
    });
    it('negative three to negative 2', async () => {
      const twofiftyfour = await fromBuffer(b)(-3, -2);
      // @ts-ignore
      expect(twofiftyfour).to.deep.eql(b.slice(253, 254));
      // @ts-ignore
      expect(Array.from(twofiftyfour)).to.deep.eql([253]);
    });
  });

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
      // @ts-ignore
      box
        .stub(fs, 'readFile')
        .callsFake((p: string, f: (err: NodeJS.ErrnoException, data: Buffer) => void) => {
          switch (p) {
            case 'file://local/file':
              // @ts-ignore
              f(undefined, Buffer.from(range(256)));
              break;
            case 'file://fails':
              // @ts-ignore
              f(new Error('I/O Error'), undefined);
              break;
            case 'file://not/found':
              // @ts-ignore
              f(new Error('File not found'), undefined);
              break;
            default:
              // @ts-ignore
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
      const c: chunker = fromNodeFile(path);
      const all: Uint8Array = await c();
      // @ts-ignore
      expect(all).to.deep.eql(b);
      // @ts-ignore
      expect(Array.from(all)).to.deep.eql(r);
    });
    it('one', async () => {
      const c: chunker = fromNodeFile(path);
      const one: Uint8Array = await c(1, 2);
      // @ts-ignore
      expect(one).to.deep.eql(b.slice(1, 2));
      // @ts-ignore
      expect(Array.from(one)).to.deep.eql([1]);
    });
    it('negative one', async () => {
      const twofiftyfive: Uint8Array = await fromNodeFile(path)(-1);
      // @ts-ignore
      expect(twofiftyfive).to.deep.eql(b.slice(255));
      // @ts-ignore
      expect(Array.from(twofiftyfive)).to.deep.eql([255]);
    });
    it('negative two', async () => {
      const twofiftyfour: Uint8Array = await fromNodeFile(path)(-2, -1);
      // @ts-ignore
      expect(twofiftyfour).to.deep.eql(b.slice(254, 255));
      // @ts-ignore
      expect(Array.from(twofiftyfour)).to.deep.eql([254]);
    });
    it('missing', async () => {
      try {
        const c: chunker = fromNodeFile('file://not/found');
        await c();
        expect.fail();
      } catch (e) {
        expect(e).to.be.an('error');
      }
    });
    it('broken stream all', async () => {
      try {
        const c: chunker = fromNodeFile('file://fails');
        await c();
        expect.fail();
      } catch (e) {
        expect(e).to.be.an('error');
      }
    });
    it('broken stream some', async () => {
      try {
        const c: chunker = fromNodeFile('file://fails');
        await c(1);
        expect.fail();
      } catch (e) {
        expect(e).to.be.an('error');
      }
    });
  });

  describe('fromUrl', () => {
    const baseDir = `${__dirname}/temp/artifacts`;
    const path = 'testfile.bin';
    const testFile = `${baseDir}/${path}`;
    const r = range(256);
    const b = new Uint8Array(r);
    // @ts-ignore
    let server;
    before(async () => {
      await fs.promises.mkdir(baseDir, { recursive: true });
      fs.writeFileSync(testFile, b);
      // response to all requests with this tdf file
      server = createServer((req, res) => {
        // @ts-ignore
        if (req.url.endsWith('error')) {
          send(req, req.url)
            // @ts-ignore
            .on('stream', (stream) => {
              stream.on('open', () => {
                stream.emit('error', new Error('Something 500-worthy'));
              });
            })
            .pipe(res);
        } else {
          send(req, `${baseDir}${req.url}`).pipe(res);
        }
      });
      return server.listen();
    });
    after(async () => {
      // @ts-ignore
      return server.close(() => {
        // @ts-ignore
        server.unref();
      });
    });
    // @ts-ignore
    const urlFor = (p) => `http://localhost:${server.address().port}/${p}`;
    it('all', async () => {
      const c: chunker = fromUrl(urlFor(path));
      const all: Uint8Array = await c();
      // @ts-ignore
      expect(all).to.deep.eql(b);
      // @ts-ignore
      expect(Array.from(all)).to.deep.eql(r);
    });
    it('one', async () => {
      const c: chunker = fromUrl(urlFor(path));
      const one: Uint8Array = await c(1, 2);
      // @ts-ignore
      expect(one).to.deep.eql(b.slice(1, 2));
      // @ts-ignore
      expect(Array.from(one)).to.deep.eql([1]);
    });
    it('negative one', async () => {
      const twofiftyfive: Uint8Array = await fromUrl(urlFor(path))(-1);
      // @ts-ignore
      expect(twofiftyfive).to.deep.eql(b.slice(255));
      // @ts-ignore
      expect(Array.from(twofiftyfive)).to.deep.eql([255]);
    });
    it('negative two', async () => {
      try {
        await fromUrl(urlFor(path))(-2, -1);
        expect.fail();
      } catch (e) {
        expect(e).to.be.an('error');
      }
    });
    it('unsatisiable', async () => {
      try {
        await fromUrl(urlFor(path))(12, 5);
        expect.fail();
      } catch (e) {
        expect(e.message).to.match(/failed with status code 416/);
      }
    });
    it('broken stream all', async () => {
      try {
        const c: chunker = fromUrl(urlFor('error'));
        await c();
        expect.fail();
      } catch (e) {
        expect(e.message).to.match(/failed with status code 404/);
      }
    });
    it('broken stream some', async () => {
      try {
        const c: chunker = fromUrl(urlFor('error'));
        await c(1);
        expect.fail();
      } catch (e) {
        expect(e.message).to.match(/failed with status code 404/);
      }
    });
  });
});
