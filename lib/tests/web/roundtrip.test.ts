import { expect } from '@esm-bundle/chai';
import { type AuthProvider, HttpRequest, withHeaders } from '../../src/auth/auth.js';

import { NanoTDFClient } from '../../src/nanoclients.js';
import NanoTDF from '../../src/nanotdf/NanoTDF.js';
import { OpenTDF } from '../../src/opentdf.js';
import { fromString } from '../../src/seekable.js';

const authProvider = <AuthProvider>{
  updateClientPublicKey: async () => {
    /* mocked function */
  },
  withCreds: async (req: HttpRequest): Promise<HttpRequest> =>
    withHeaders(req, {
      Authorization:
        'Bearer dummy-auth-token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZGYiLCJzdWIiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMn0.XFu4sQxAd6n-b7urqTdQ-I9zKqKSQtC04unHsMSpJjc',
    }),
};

const kasEndpoint = 'http://localhost:3000';
const platformUrl = 'http://localhost:3000';

describe('Local roundtrip Tests', () => {
  it(`ztdf roundtrip string`, async () => {
    const client = new OpenTDF({
      authProvider,
      defaultReadOptions: {
        allowedKASEndpoints: [kasEndpoint],
      },
    });
    const cipherTextStream = await client.createZTDF({
      autoconfigure: false,
      defaultKASEndpoint: kasEndpoint,
      source: { type: 'chunker', location: fromString('hello world') },
    });
    const cipherManifest = await cipherTextStream.manifest;
    const kao = cipherManifest?.encryptionInformation?.keyAccess[0];
    expect(kao).to.contain({
      url: kasEndpoint,
      kid: 'e1',
      type: 'ec-wrapped',
      protocol: 'kas',
      schemaVersion: '1.0',
    });
    const cipherTextArray = new Uint8Array(await new Response(cipherTextStream).arrayBuffer());

    const nanotdfParsed = await client.read({
      source: { type: 'buffer', location: cipherTextArray },
    });

    const metadata = (await nanotdfParsed.metadata) as never;
    expect(metadata['hello']['kind']['value']).to.equal('world');

    const actual = await new Response(nanotdfParsed).arrayBuffer();
    expect(new TextDecoder().decode(actual)).to.be.equal('hello world');
  });
  it(`ztdf roundtrip string with platformUrl`, async () => {
    const client = new OpenTDF({
      authProvider,
      platformUrl,
    });
    const cipherTextStream = await client.createZTDF({
      autoconfigure: false,
      defaultKASEndpoint: kasEndpoint,
      source: { type: 'chunker', location: fromString('hello world') },
    });
    const cipherManifest = await cipherTextStream.manifest;
    const kao = cipherManifest?.encryptionInformation?.keyAccess[0];
    expect(kao).to.contain({
      url: kasEndpoint,
      kid: 'e1',
      type: 'ec-wrapped',
      protocol: 'kas',
      schemaVersion: '1.0',
    });
    const cipherTextArray = new Uint8Array(await new Response(cipherTextStream).arrayBuffer());

    const nanotdfParsed = await client.read({
      source: { type: 'buffer', location: cipherTextArray },
    });

    const metadata = (await nanotdfParsed.metadata) as never;
    expect(metadata['hello']['kind']['value']).to.equal('world');

    const actual = await new Response(nanotdfParsed).arrayBuffer();
    const decoded = new TextDecoder().decode(actual);
    expect(decoded).to.be.equal('hello world');
  });
  it(`ztdf roundtrip string without platform url nor allowedList should fail`, async () => {
    const client = new OpenTDF({
      authProvider,
    });
    const cipherTextStream = await client.createZTDF({
      autoconfigure: false,
      defaultKASEndpoint: kasEndpoint,
      source: { type: 'chunker', location: fromString('hello world') },
    });
    const cipherManifest = await cipherTextStream.manifest;
    const kao = cipherManifest?.encryptionInformation?.keyAccess[0];
    expect(kao).to.contain({
      url: kasEndpoint,
      kid: 'e1',
      type: 'ec-wrapped',
      protocol: 'kas',
      schemaVersion: '1.0',
    });
    const cipherTextArray = new Uint8Array(await new Response(cipherTextStream).arrayBuffer());

    try {
      await client.read({
        source: { type: 'buffer', location: cipherTextArray },
      });
    } catch (e) {
      expect(e.message).to.contains('platformUrl is required when allowedKasEndpoints is empty');
      return;
    }
  });
  it(`ztdf roundtrip string with useBasePublicKey`, async () => {
    const client = new OpenTDF({
      authProvider,
      platformUrl,
    });
    const cipherTextStream = await client.createZTDF({
      autoconfigure: false,
      defaultKASEndpoint: kasEndpoint,
      source: { type: 'chunker', location: fromString('hello world') },
    });
    const cipherManifest = await cipherTextStream.manifest;
    const kao = cipherManifest?.encryptionInformation?.keyAccess[0];
    expect(kao).to.contain({
      url: kasEndpoint,
      kid: 'e1',
      type: 'ec-wrapped',
      protocol: 'kas',
      schemaVersion: '1.0',
    });
    const cipherTextArray = new Uint8Array(await new Response(cipherTextStream).arrayBuffer());

    const nanotdfParsed = await client.read({
      source: { type: 'buffer', location: cipherTextArray },
    });

    const metadata = (await nanotdfParsed.metadata) as never;
    expect(metadata['hello']['kind']['value']).to.equal('world');

    const actual = await new Response(nanotdfParsed).arrayBuffer();
    const decoded = new TextDecoder().decode(actual);
    expect(decoded).to.be.equal('hello world');
  });

  for (const ecdsaBinding of [false, true]) {
    const bindingType = ecdsaBinding ? 'ecdsa' : 'gmac';
    it(`nano roundtrip string (${bindingType} policy binding)`, async () => {
      const client = new OpenTDF({
        authProvider,
        defaultReadOptions: {
          allowedKASEndpoints: [kasEndpoint],
        },
      });
      const cipherText = await client.createNanoTDF({
        bindingType,
        defaultKASEndpoint: kasEndpoint,
        source: { type: 'chunker', location: fromString('hello world') },
      });
      const nanotdfParsed = await client.read({
        source: { type: 'stream', location: cipherText },
      });
      expect(nanotdfParsed.header?.kas?.url).to.equal(kasEndpoint);
      expect(nanotdfParsed.header?.kas?.identifier).to.equal('e1');

      const actual = await new Response(nanotdfParsed).arrayBuffer();
      expect(new TextDecoder().decode(actual)).to.be.equal('hello world');
    });
    it(`roundtrip string (${bindingType} policy binding, deprecated API)`, async () => {
      const client = new NanoTDFClient({ authProvider, kasEndpoint, platformUrl });
      const cipherText = await client.encrypt('hello world', { ecdsaBinding });
      const client2 = new NanoTDFClient({ authProvider, kasEndpoint, platformUrl });
      const nanotdfParsed = NanoTDF.from(cipherText);

      expect(nanotdfParsed.header.kas.url).to.equal(kasEndpoint);
      expect(nanotdfParsed.header.kas.identifier).to.equal('e1');

      const actual = await client2.decrypt(cipherText);
      expect(new TextDecoder().decode(actual)).to.be.equal('hello world');
    });
  }
});
