import { expect } from 'chai';
// TODO Validate http urls resolve to fetch requests
// import fs from 'node:fs';
// import { createServer, Server } from 'node:http';
// import send from 'send';
import { createSandbox, type SinonSpy, type SinonSandbox } from 'sinon';

import { FileClient } from '../../../tdf3/src/FileClient';
import { Client as ClientTdf3 } from '../../../tdf3/src/client/index';
import { EncryptParamsBuilder } from '../../../tdf3/src/client/builders';

describe('FileClient', () => {
  let box: SinonSandbox;
  beforeEach(() => {
    box = createSandbox();
  });
  afterEach(() => {
    box.restore();
  });

  let client: ClientTdf3;
  let encrypt: SinonSpy;
  let decrypt: SinonSpy;
  beforeEach(() => {
    decrypt = box.fake();
    encrypt = box.fake();
    client = { decrypt, encrypt } as unknown as ClientTdf3;
  });
  describe('encrypt', () => {
    it('file source bare', async () => {
      const fileClient = new FileClient(client);
      await fileClient.encrypt('README.md');
      expect(encrypt.callCount).to.equal(1);
      const params = encrypt.args[0][0];
      expect(params).to.contain({ offline: true });
      expect(params.source).to.be.an.instanceOf(ReadableStream);
    });
    it('file source url', async () => {
      const fileClient = new FileClient(client);
      await fileClient.encrypt('file://./README.md');
      expect(encrypt.callCount).to.equal(1);
      const params = encrypt.args[0][0];
      expect(params).to.contain({ offline: true });
      expect(params.source).to.be.an.instanceOf(ReadableStream);
    });
    it('dissems', async () => {
      const fileClient = new FileClient(client);
      await fileClient.encrypt('README.md', ['a', 'b']);
      expect(encrypt.callCount).to.equal(1);
      const params = encrypt.args[0][0];
      expect(params).to.deep.include({ scope: { attributes: [], dissem: ['a', 'b'] } });
    });
    it('attributes', async () => {
      const fileClient = new FileClient(client);
      await fileClient.encrypt(
        'README.md',
        [],
        new EncryptParamsBuilder()
          .withAttributes([{ attribute: 'https://hay.co/attr/a/value/1' }])
          .build()
      );
      expect(encrypt.callCount).to.equal(1);
      const params = encrypt.args[0][0];
      expect(params).to.deep.include({
        scope: { attributes: [{ attribute: 'https://hay.co/attr/a/value/1' }], dissem: [] },
      });
    });
  });

  describe('decrypt', () => {
    it('file source bare', async () => {
      const fileClient = new FileClient(client);
      const location = 'README.md';
      await fileClient.decrypt(location);
      expect(decrypt.callCount).to.equal(1);
      const params = decrypt.args[0][0];
      console.log(params);
      expect(params).to.deep.include({ source: { location, type: 'file-node' } });
    });
    it('file source url', async () => {
      const fileClient = new FileClient(client);
      const location = 'file://./README.md';
      await fileClient.decrypt(location);
      expect(decrypt.callCount).to.equal(1);
      const params = decrypt.args[0][0];
      console.log(params);
      expect(params).to.deep.include({ source: { location, type: 'file-node' } });
    });
  });
});
