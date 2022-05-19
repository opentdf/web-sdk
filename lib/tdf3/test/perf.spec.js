/* global BigUint64Array */

import { promisify } from 'util';
import { assert, expect } from 'chai';
import { createReadStream, createWriteStream, promises, readFileSync, statSync } from 'fs';
import { createServer } from 'http';
import send from 'send';
import JSZip from 'jszip';
import { pipeline } from 'stream';
import { createSandbox } from 'sinon';

import { Client, TDF } from '../src';
import getMocks from '../mocks';

const Mocks = getMocks();

const pipelinePromise = promisify(pipeline);

const baseDir = `${__dirname}/temp/perf`;

// First, generate sample data. Use this as a timing/memory usage baseline.
// This will normalize the other tests and keep score.
// We will generate files from 1k to 10GB on an exponential curve.
// For now the gigabyte one is commented out..
const sizes = {
  // Takes ~ 5ms to create, 25ms to round trip on my computer
  '1-KiB': 2 ** 10,
  // '10-KiB': 10 * 2 ** 10,
  '100-KiB': 100 * 2 ** 10,
  // Takes about 1s to create file, 5s to round trip on my computer
  // '1-MiB': 2 ** 20,
  // Takes about 400ms to create file, 1m to round trip on my computer
  // NOTE the timeout for a mocha test is currently set to 20s, so these
  // tests will not run with the current settings (30s timeout, 3 iterations)
  // '16-MiB': 16 * 2 ** 20,
  // Takes about 1.5s to create file, 2m20s to round trip on my computer
  // '64-MiB': 64 * 2 ** 20,
  // Takes about 3s to create file, 20s to round trip on my computer
  // '256-MiB': 256 * 2 ** 20,
  // Takes about 10s to create file, 1m to round trip on my computer.
  // 56s encrypt, 3.3s decrypt
  // '1-GiB': 1 * 2 ** 30,
  // 26s to initialize file, 2m encrypt, 3m decrypt
  // '3-GiB': 3 * 2 ** 30,
  // '4-GiB': 4 * 2 ** 30,
  // '8-GiB': 8 * 2 ** 30,
};

async function* gen(size, chunksize = 1024) {
  let a = new BigUint64Array(chunksize);
  // number of ints in the array
  let j = 0;
  for (let i = 0n; i < size; i = i + 8n) {
    a[j++] = i;
    if (j == chunksize) {
      yield new Uint8Array(a.buffer);
      a = new BigUint64Array(chunksize);
      j = 0;
    }
  }
  if (j > 0) {
    yield new Uint8Array(a.buffer, 0, j * 8);
  }
}

async function createTempData() {
  await promises.mkdir(baseDir, { recursive: true });
  let plains = {};
  for (const [name, size] of Object.entries(sizes)) {
    const start = Date.now();
    const path = `${baseDir}/plain-${name}.tmp`;
    const stream = createWriteStream(path, { flags: 'w' });
    await pipelinePromise(gen(size), stream);
    await Object.call(stream, promisify(stream.end));
    const end = Date.now();
    const delay = end - start;
    plains[name] = {
      delay,
      name,
      path,
      size,
    };
  }
  return plains;
}

let plainFiles;

before(async () => {
  plainFiles = await createTempData();
});

const sourceFactory = (sourceType, server) => (name) => {
  switch (sourceType) {
    case 'remote-remote':
      return {
        type: 'remote',
        location: `http://localhost:${server.address().port}/${name}`,
      };
    case 'file-node':
      return {
        type: 'file-node',
        location: `${baseDir}/${name}`,
      };
    case 'file-stream':
      return {
        type: 'stream',
        location: createReadStream(`${baseDir}/${name}`),
      };
    default:
      assert(false, `Unrecognized data source type: ${sourceType}`);
  }
};

const kasPublicKey = TDF.extractPemFromKeyString(Mocks.kasPublicKey);

async function correctnessTrial(plainFile, sourceType, sourceSize, trialType = 'correctness') {
  const expectedVal = readFileSync(plainFile);
  const kasUrl = `http://localhost:4000/`;

  let server;
  if (/^remote/.exec(sourceType)) {
    server = createServer((req, res) => {
      send(req, `${baseDir}${req.url}`).pipe(res);
    });
    server.listen();
  }
  const makeSourceFor = sourceFactory(sourceType, server);

  const sandbox = createSandbox();
  const tdf1 = TDF.create();
  sandbox.replace(
    TDF,
    'create',
    sandbox.fake(() => tdf1)
  );
  sandbox.spy(tdf1, '_generateManifest');
  sandbox.stub(tdf1, 'unwrapKey').callsFake(async () => {
    const keyInfo = tdf1._generateManifest.lastCall.args[0];
    return {
      reconstructedKeyBinary: keyInfo.unwrappedKeyBinary,
      metadata: {},
    };
  });

  const windowSize = trialType === 'correctness' ? 1024 : 8 * 1024 * 1024;

  async function pipeTest() {
    const initialMemory = process.memoryUsage();
    const client = new Client.Client({
      kasEndpoint: kasUrl,
      kasPublicKey,
      organizationName: 'realm',
      clientId: 'id',
      clientSecret: 'secret',
    });

    const eo = await Mocks.getEntityObject();
    const scope = Mocks.getScope();
    const tdfOutputStream = createWriteStream(`${baseDir}/teststream-${sourceSize}.zip`, {
      encoding: 'binary',
    });
    const startEncrypt = Date.now();
    const encryptPromise = client.encrypt({
      keypair: { publicKey: Mocks.entityPublicKey, privateKey: Mocks.entityPrivateKey },
      eo,
      metadata: Mocks.getMetadataObject(),
      offline: true,
      output: tdfOutputStream,
      scope,
      source: createReadStream(plainFile),
      windowSize,
    });
    const finishPromise = new Promise((resolve, reject) => {
      tdfOutputStream.on('finish', resolve).on('error', reject);
    });
    await Promise.all([encryptPromise, finishPromise]);
    const endEncrypt = Date.now();
    assert(tdf1._generateManifest.calledOnce);
    const midpointMemory = process.memoryUsage();

    const plainOutputStream = createWriteStream(`${baseDir}/teststream-${sourceSize}.out`);
    const startDecrypt = Date.now();
    const finishDecryptPromise = new Promise((resolve, reject) => {
      plainOutputStream.on('finish', resolve).on('error', reject);
    });
    const decryptPromise = client.decrypt({
      eo,
      keypair: { publicKey: Mocks.entityPublicKey, privateKey: Mocks.entityPrivateKey },
      output: plainOutputStream,
      source: makeSourceFor(`teststream-${sourceSize}.zip`),
    });
    await Promise.all([finishDecryptPromise, decryptPromise]);
    const endDecrypt = Date.now();
    const endMemory = process.memoryUsage();

    // check teststream.out === inpt
    if (trialType === 'correctness') {
      expect(readFileSync(`${baseDir}/teststream-${sourceSize}.out`)).to.eql(expectedVal);
      // now check what happens if the integrity is mucked with
      // open up the zip we just created, and update the segment integrity information
      const zip = new JSZip();
      const zipFile = await zip.loadAsync(readFileSync(`${baseDir}/teststream-${sourceSize}.zip`));
      const manifest = await zipFile.file('0.manifest.json').async('string');

      const newManifest = JSON.parse(manifest);
      newManifest.encryptionInformation.integrityInformation.segments[0].hash =
        'fkdkldsfhkdsfjhfkdsj';

      zipFile.remove('0.manifest.json');
      zipFile.file('0.manifest.json', JSON.stringify(newManifest));

      await new Promise((resolve, reject) => {
        zip
          .generateNodeStream({ type: 'nodebuffer', streamFiles: true })
          .pipe(createWriteStream(`${baseDir}/teststream2.zip`))
          .on('finish', resolve)
          .on('error', reject);
      });

      let errorMessage;
      try {
        await client.decrypt({
          eo,
          keypair: { publicKey: Mocks.entityPublicKey, privateKey: Mocks.entityPrivateKey },
          output: createWriteStream(`${baseDir}/teststream2.out`),
          source: makeSourceFor('teststream2.zip'),
        });
      } catch (e) {
        errorMessage = e.message;
      }

      assert.equal(errorMessage, 'Failed integrity check on root signature');
    } else {
      const stats = statSync(`${baseDir}/teststream-${sourceSize}.out`);
      const fileSizeInBytes = stats.size;
      expect(fileSizeInBytes).to.eql(sourceSize);
    }

    if (server) {
      server.close(() => {
        server.unref();
        server = null;
      });
    }
    return {
      encryptTime: endEncrypt - startEncrypt,
      decryptTime: endDecrypt - startDecrypt,
      memoryTrack: [initialMemory, midpointMemory, endMemory],
    };
  }
  try {
    return await pipeTest();
  } finally {
    sandbox.restore();
  }
}

/**
 * These perf tests compare different stream types and will hopefully
 * compare different crypto backends once we enable crypto backend selection.
 * The stream types and crypto types available depend to some extent on the
 * runtime in use.
 */
describe('Local Performance Tests', function () {
  const iterations = 5;
  const results = [];
  after(() => {
    // FIXME don't depend on key order being stable
    console.log(Object.keys(results[0]).join(','));
    for (const result of results) {
      console.log(Object.values(result).join(','));
    }
  });

  // TODO Enable crypto alternatives
  for (const cryptoType of ['node-crypto']) {
    for (const streamType of ['remote-remote', 'file-node', 'file-stream']) {
      describe(`I/O Type: ${streamType}`, function () {
        for (const [name, sizeInBytes] of Object.entries(sizes)) {
          it(`Round ${name}`, async function () {
            const start = Date.now();
            let et = 0,
              dt = 0;
            const { path, delay } = plainFiles[name];
            const mt = [{}, {}, {}];
            for (let i = 0; i < iterations; i++) {
              const { encryptTime, decryptTime, memoryTrack } = await correctnessTrial(
                path,
                streamType,
                sizeInBytes,
                'performance'
              );
              et += encryptTime;
              dt += decryptTime;
              // NOTE this memory tracking is very informative
              for (let i = 0; i < 3; i++) {
                for (const [memType, bytes] of Object.entries(memoryTrack[i])) {
                  mt[i][memType] = (mt[i][memType] || 0) + bytes;
                }
              }
            }
            const end = Date.now();
            const ms = end - start;
            const result = {
              cryptoType,
              streamType,
              sizeInBytes,
              encryptTimeMs: Math.floor(et / iterations),
              decryptTimeMs: Math.floor(dt / iterations),
              durationMs: Math.floor(ms / iterations),
              normalizationFactor: 1 + delay,
              normalizedScore: ms / (1 + delay),
              heap1: mt[0].heapUsed / iterations,
              heap2: mt[1].heapUsed / iterations,
              heap3: mt[2].heapUsed / iterations,
              external1: mt[0].external / iterations,
              external2: mt[1].external / iterations,
              external3: mt[2].external / iterations,
              arrayBuffers1: mt[0].arrayBuffers / iterations,
              arrayBuffers2: mt[1].arrayBuffers / iterations,
              arrayBuffers3: mt[2].arrayBuffers / iterations,
            };
            results.push(result);
            console.log(
              `${cryptoType}:${streamType}:${name} Total Duration: ${ms}, Normalized: ${result.normalizedScore}, EncryptTime: ${result.encryptTimeMs}, DecryptTime: ${result.decryptTimeMs}`
            );
          });
        }
      });
    }
  }
});

describe('Local Correctness Tests', function () {
  const cryptoTypes = ['node-crypto'];
  for (const streamType of ['file-node', 'file-stream']) {
    for (const encType of cryptoTypes) {
      for (const decType of cryptoTypes) {
        it(`Round trip ${streamType} ${encType}->${decType}`, async function () {
          const { path, size } = plainFiles['1-KiB'];
          // TODO Update correctness trial to take crypto types
          await correctnessTrial(path, streamType, size, 'correctness');
        });
      }
    }
  }
});
