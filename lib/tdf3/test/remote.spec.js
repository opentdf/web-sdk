import { assert } from 'chai';
import { promises, createReadStream, createWriteStream } from 'fs';
import { createServer } from 'http';
import send from 'send';

import { TDF } from '../src';
import getMocks from '../mocks';

const Mocks = getMocks();

const baseDir = `${__dirname}/temp/artifacts`;

let server;

before(async () => {
  promises.mkdir(baseDir, { recursive: true });

  // response to all requests with this tdf file
  server = createServer((req, res) => {
    // `send` is an http `range` header supporting file server
    // assert(req.url, '/teststream3.zip');
    send(req, `${baseDir}${req.url}`).pipe(res);
  });

  return server.listen();
});

after(async () => {
  return server.close(() => {
    server.unref();
  });
});

describe('Remote Policies', () => {
  it('returns the policy object given a url', async () => {
    const kasPublicKey = TDF.extractPemFromKeyString(Mocks.kasPublicKey);

    const contentStream = createReadStream(`${__dirname}/../mocks/client/entity.json`);
    const kasUrl = Mocks.getKasUrl();

    const tdf1 = TDF.create()
      .setPrivateKey(Mocks.entityPrivateKey)
      .setPublicKey(Mocks.entityPublicKey)
      .setEncryption({
        type: 'split',
        cipher: 'aes-256-gcm',
      })
      .addKeyAccess({
        type: 'wrapped',
        url: kasUrl,
        publicKey: kasPublicKey,
        metadata: JSON.stringify(Mocks.getMetadataObject()),
      })
      .setPolicy(Mocks.getPolicyObject())
      .setDefaultSegmentSize(100)
      // set root sig and segment types
      .setIntegrityAlgorithm('hs256', 'gmac')
      .addContentStream(contentStream);

    const testStreamZip = `${baseDir}/teststream3.zip`;
    const writingStream = createWriteStream(testStreamZip);

    await tdf1.writeStream(writingStream);

    await new Promise((resolve) => {
      writingStream.on('finish', resolve);
    });

    const url = `http://localhost:${server.address().port}/teststream3.zip`;

    const policy = await TDF.getPolicyFromRemoteTDF(url);
    const parsedPolicy = JSON.parse(policy);
    assert(parsedPolicy.uuid.length, 36);
  });
});
