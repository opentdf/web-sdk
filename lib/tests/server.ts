import * as jose from 'jose';
import { createServer, IncomingMessage, RequestListener } from 'node:http';

import { base64 } from '../src/encodings/index.js';
import { decryptWithPrivateKey, encryptWithPublicKey } from '../tdf3/src/crypto/index.js';
import { getMocks } from './mocks/index.js';
import { getHkdfSalt, Header } from '../src/nanotdf/index.js';
import { keyAgreement, pemPublicToCrypto } from '../src/nanotdf-crypto/index.js';
import { generateRandomNumber } from '../src/nanotdf-crypto/generateRandomNumber.js';
import { removePemFormatting } from '../tdf3/src/crypto/crypto-utils.js';
import { Binary } from '../tdf3/index.js';
import { valueFor } from './web/policy/mock-attrs.js';
import { AttributeAndValue } from '../src/policy/attributes.js';
import { ztdfSalt } from '../tdf3/src/crypto/salt.js';

import { create, toJsonString, fromJson } from '@bufbuild/protobuf';
import { ValueSchema } from '@bufbuild/protobuf/wkt';
import {
  PolicyRewrapResultSchema,
  KeyAccessRewrapResultSchema,
  RewrapResponseSchema,
  UnsignedRewrapRequestSchema,
} from '../src/platform/kas/kas_pb.js';

const Mocks = getMocks();

function range(start: number, end: number): Uint8Array {
  const result = [];
  for (let i = start; i <= end; i++) {
    result.push(i);
  }
  return new Uint8Array(result);
}

function concat(b: ArrayBufferView[]) {
  const length = b.reduce((lk, ak) => lk + ak.byteLength, 0);
  const buf = new Uint8Array(length);
  let offset = 0;
  for (const v of b) {
    const uint8view = new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
    buf.set(uint8view, offset);
    offset += uint8view.byteLength;
  }
  return buf;
}

function getBody(request: IncomingMessage): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const bodyParts: Uint8Array[] = [];
    request
      .on('data', (chunk) => {
        bodyParts.push(chunk);
      })
      .on('end', () => {
        resolve(concat(bodyParts));
      })
      .on('error', reject);
  });
}

const kas: RequestListener = async (req, res) => {
  console.log('[INFO]: server request: ', req.method, req.url, req.headers);
  res.setHeader(
    'Access-Control-Allow-Headers',
    [
      'authorization',
      'content-type',
      'dpop',
      'range',
      'x-test-response',
      'x-test-response-message',
      'roundtrip-test-response',
      'connect-protocol-version',
      'connect-streaming-protocol-version',
    ].join(', ')
  );
  res.setHeader('Access-Control-Allow-Origin', '*');
  // GET should be allowed for everything except rewrap, POST only for rewrap but IDC
  res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, GET, POST');
  try {
    const url = new URL(req.url || '', `http://${req?.headers?.host}`);
    if (req.method === 'OPTIONS') {
      res.statusCode = 200;
      console.log('[DEBUG] CORS response 200');
      res.end();
    } else if (req.headers['roundtrip-test-response']) {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ status: 'ok' }));
      return;
    } else if (url.pathname === '/kas.AccessService/PublicKey') {
      const body = await getBody(req);
      const bodyText = new TextDecoder().decode(body);
      const params = JSON.parse(bodyText);
      const algorithm = params.algorithm || 'rsa:2048';

      if (!['ec:secp256r1', 'rsa:2048'].includes(algorithm)) {
        console.log(`[DEBUG] invalid algorithm [${algorithm}]`);
        res.writeHead(400);
        res.end(`{"error": "Invalid algorithm [${algorithm}]"}`);
        return;
      }
      const fmt = params.fmt || 'pkcs8';
      if (!['jwks', 'pkcs8'].includes(fmt)) {
        console.log(`[DEBUG] invalid fmt [${fmt}]`);
        res.writeHead(400);
        res.end(`{"error": "Invalid fmt [${fmt}]"}`);
        return;
      }
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 200;
      const publicKey = 'ec:secp256r1' == algorithm ? Mocks.kasECCert : Mocks.kasPublicKey;
      const kid = 'ec:secp256r1' == algorithm ? 'e1' : 'r1';
      res.end(JSON.stringify({ kid, publicKey }));
      return;
    } else if (url.pathname === '/kas.AccessService/Rewrap') {
      // For testing error conditions x-test-response, immediate error returns, control by individual test
      if (req.headers['x-test-response']) {
        const statusCode = parseInt(req.headers['x-test-response'] as string);
        res.writeHead(statusCode);
        switch (statusCode) {
          case 400:
            const statusMessage = parseInt(req.headers['x-test-response-message'] as string);
            res.end(JSON.stringify({ error: statusMessage }));
            return;
          case 401:
            res.end(JSON.stringify({ error: 'Unauthorized' }));
            return;
          case 403:
            res.end(JSON.stringify({ error: 'Forbidden' }));
            return;
          case 500:
            res.end(JSON.stringify({ error: 'Internal server error' }));
            return;
        }
      }
      if (req.method !== 'POST') {
        console.error(`[ERROR] /v2/rewrap only accepts POST verbs, received [${req.method}]`);
        res.writeHead(405);
        res.end(`{"error": "Invalid method [${req.method}]"}`);
        return;
      }
      console.log('[INFO]: rewrap request meta: ', req.method, req.url, req.headers);
      // NOTE: Real KAS will validate authorization and dpop here. simple Invalid check
      if (req.headers['authorization'] == 'Invalid') {
        res.writeHead(401);
        res.end(JSON.stringify({ code: 'unauthenticated', message: 'unauthenticated' }));
        return;
      }
      const body = await getBody(req);
      const bodyText = new TextDecoder().decode(body);
      const { signedRequestToken } = JSON.parse(bodyText);
      // NOTE: Real KAS will verify JWT here
      const { requestBody } = jose.decodeJwt(signedRequestToken);

      if (requestBody === 'mock-request-body') {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ status: 'ok' }));
        return;
      }

      const rewrap = fromJson(UnsignedRewrapRequestSchema, JSON.parse(requestBody as string));
      console.log('[INFO]: rewrap request body: ', rewrap);
      const clientPublicKey = await pemPublicToCrypto(rewrap.clientPublicKey);
      if (!clientPublicKey || clientPublicKey.type !== 'public') {
        res.writeHead(400);
        res.end('{"error": "Invalid client public key"}');
        return;
      }
      const keyAccessObject = rewrap.requests?.[0]?.keyAccessObjects?.[0]?.keyAccessObject;
      const kaoheader = keyAccessObject?.header;
      const isZTDF = !kaoheader || kaoheader.length === 0;
      if (isZTDF) {
        const wk = keyAccessObject?.wrappedKey;
        if (!wk || wk.length === 0) {
          res.writeHead(400);
          res.end('{"error": "Invalid wrapped key"}');
          return;
        }
        const isECWrapped = keyAccessObject?.kid == 'e1';
        // Decrypt the wrapped key from TDF3
        let dek: Binary;
        if (isECWrapped) {
          if (!keyAccessObject?.ephemeralPublicKey) {
            res.writeHead(400);
            res.end('{"error": "Nil ephemeral public key"}');
            return;
          }
          const ephemeralKey: CryptoKey = await pemPublicToCrypto(
            keyAccessObject?.ephemeralPublicKey
          );
          const kasPrivateKeyBytes = base64.decodeArrayBuffer(
            removePemFormatting(Mocks.kasECPrivateKey)
          );
          const kasPrivateKey = await crypto.subtle.importKey(
            'pkcs8',
            kasPrivateKeyBytes,
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            ['deriveBits', 'deriveKey']
          );
          const kek = await keyAgreement(kasPrivateKey, ephemeralKey, {
            hkdfSalt: await ztdfSalt,
            hkdfHash: 'SHA-256',
          });
          const iv = wk.slice(0, 12);
          const wrappedKey = wk.slice(12);
          const dekab = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, kek, wrappedKey);
          dek = Binary.fromArrayBuffer(dekab);
        } else {
          dek = await decryptWithPrivateKey(Binary.fromArrayBuffer(wk), Mocks.kasPrivateKey);
        }
        if (clientPublicKey.algorithm.name == 'RSA-OAEP') {
          const cek = await encryptWithPublicKey(dek, rewrap.clientPublicKey);
          const reply = create(RewrapResponseSchema, {
            responses: [
              create(PolicyRewrapResultSchema, {
                results: [
                  create(KeyAccessRewrapResultSchema, {
                    metadata: {
                      hello: create(ValueSchema, {
                        kind: { case: 'stringValue', value: 'world' },
                      }),
                    },
                    result: {
                      case: 'kasWrappedKey',
                      value: new Uint8Array(cek.asArrayBuffer()),
                    },
                    keyAccessObjectId:
                      rewrap.requests?.[0]?.keyAccessObjects?.[0]?.keyAccessObjectId || '',
                  }),
                ],
              }),
            ],
          });
          res.statusCode = 200;
          res.setHeader('Content-Type', 'application/json');
          res.end(toJsonString(RewrapResponseSchema, reply));
          return;
        }
        const sessionKeyPair = await crypto.subtle.generateKey(
          {
            name: 'ECDH',
            namedCurve: 'P-256',
          },
          false,
          ['deriveBits', 'deriveKey']
        );
        const kek = await keyAgreement(sessionKeyPair.privateKey, clientPublicKey, {
          hkdfSalt: await ztdfSalt,
          hkdfHash: 'SHA-256',
        });
        const iv = generateRandomNumber(12);
        const cek = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, dek.asArrayBuffer());
        const entityWrappedKey = new Uint8Array(iv.length + cek.byteLength);
        entityWrappedKey.set(iv);
        entityWrappedKey.set(new Uint8Array(cek), iv.length);
        const reply = create(RewrapResponseSchema, {
          responses: [
            create(PolicyRewrapResultSchema, {
              results: [
                create(KeyAccessRewrapResultSchema, {
                  metadata: {
                    hello: create(ValueSchema, {
                      kind: { case: 'stringValue', value: 'world' },
                    }),
                  },
                  result: {
                    case: 'kasWrappedKey',
                    value: entityWrappedKey,
                  },
                  keyAccessObjectId:
                    rewrap.requests?.[0]?.keyAccessObjects?.[0]?.keyAccessObjectId || '',
                }),
              ],
            }),
          ],
        });

        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json');
        res.end(toJsonString(RewrapResponseSchema, reply));
        return;
      }
      // nanotdf
      console.log('[INFO] nano rewrap request body: ', rewrap);
      const { header } = Header.parse(kaoheader || new Uint8Array(base64.decodeArrayBuffer('')));
      // TODO convert header.ephemeralCurveName to namedCurve
      const nanoPublicKey = await crypto.subtle.importKey(
        'raw',
        header.ephemeralPublicKey,
        {
          name: 'ECDH',
          namedCurve: 'P-256',
        },
        true,
        []
      );

      const kasPrivateKeyBytes = base64.decodeArrayBuffer(
        removePemFormatting(Mocks.kasECPrivateKey)
      );
      const kasPrivateKey = await crypto.subtle.importKey(
        'pkcs8',
        kasPrivateKeyBytes,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveBits', 'deriveKey']
      );
      console.log('Imported kas private key!');
      const hkdfSalt = await getHkdfSalt(header.magicNumberVersion);
      const dek = await keyAgreement(kasPrivateKey, nanoPublicKey, hkdfSalt);
      const kek = await keyAgreement(kasPrivateKey, clientPublicKey, hkdfSalt);
      const dekBits = await crypto.subtle.exportKey('raw', dek);
      console.log(
        `agreeeed! dek = [${new Uint8Array(dekBits)}], kek = [${new Uint8Array(
          await crypto.subtle.exportKey('raw', kek)
        )}], byteLength = [${dekBits.byteLength}]`
      );
      const iv = generateRandomNumber(12);
      const cek = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
          tagLength: 128,
        },
        kek,
        dekBits
      );
      const cekBytes = new Uint8Array(cek);
      console.log(`responding! cek = [${cekBytes}], iv = [${iv}], tagLength = [${128}]`);
      // const doublecheck = await crypto.subtle.decrypt(
      //   { name: 'AES-GCM', iv, tagLength: 128 },
      //   kek,
      //   cek
      // );
      // console.log(`doublecheck success! dek = [${new Uint8Array(doublecheck)}]`);

      const entityWrappedKey = new Uint8Array(iv.length + cekBytes.length);
      entityWrappedKey.set(iv);
      entityWrappedKey.set(cekBytes, iv.length);
      const reply = create(RewrapResponseSchema, {
        sessionPublicKey: Mocks.kasECCert,
        responses: [
          create(PolicyRewrapResultSchema, {
            results: [
              create(KeyAccessRewrapResultSchema, {
                metadata: {
                  hello: create(ValueSchema, {
                    kind: { case: 'stringValue', value: 'people of earth' },
                  }),
                },
                result: {
                  case: 'kasWrappedKey',
                  value: entityWrappedKey,
                },
                keyAccessObjectId:
                  rewrap.requests?.[0]?.keyAccessObjects?.[0]?.keyAccessObjectId || '',
              }),
            ],
          }),
        ],
      });

      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(toJsonString(RewrapResponseSchema, reply));
      return;
    } else if (url.pathname === '/file') {
      if (req.method !== 'GET') {
        res.writeHead(405);
        res.end(`{"error": "Invalid method [${req.method}]"}`);
        return;
      }
      const start = 0;
      const end = 255;
      const fullRange = range(start, end);

      const rangeHeader = req.headers.range;
      if (rangeHeader) {
        const bytesRange = rangeHeader.replace('bytes=', '').split('-');
        let rangeData;
        let rangeStart;
        let rangeEnd;
        if (!bytesRange[0]) {
          rangeStart = parseInt(rangeHeader.replace('bytes=', ''));
          rangeData = fullRange.slice(rangeStart);
        } else {
          rangeStart = parseInt(bytesRange[0], 10);
          rangeEnd = parseInt(bytesRange[1], 10) || end;
          rangeData = fullRange.slice(rangeStart, rangeEnd + 1);

          if (rangeStart > rangeEnd) {
            res.statusCode = 416; // Range Not Satisfiable
            res.setHeader('Content-Range', `*/${end + 1}`);
            res.end();
            return;
          }
        }

        res.statusCode = 206; // Partial Content
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Length', rangeData.length);
        res.end(rangeData);
      } else {
        res.statusCode = 200; // OK
        res.setHeader('Content-Type', 'application/octet-stream');
        res.end(fullRange);
      }
    } else if (url.pathname === '/policy.attributes.AttributesService/GetAttributeValuesByFqns') {
      res.setHeader('Content-Type', 'application/json');
      const token = req.headers['authorization'] as string;
      if (!token || !token.startsWith('Bearer dummy-auth-token')) {
        res.statusCode = 401;
        res.end(JSON.stringify({ code: 'unauthenticated', message: 'unauthenticated' }));
        return;
      }

      const body = await getBody(req);
      const bodyText = new TextDecoder().decode(body);
      const params = JSON.parse(bodyText);
      const fqnAttributeValues: Record<string, AttributeAndValue> = {};
      let skipped = 0;

      for (const v of params.fqns) {
        const value = valueFor(v);
        if (!value) {
          console.error(`unable to find definition for value [${v}]`);
          skipped++;
          continue;
        }
        const attribute = value.attribute;
        if (!attribute) {
          console.error(`unable to find definition for attribute [${v}]`);
          skipped++;
          continue;
        }
        fqnAttributeValues[v] = { attribute, value };
      }

      res.setHeader('Content-Type', 'application/json');
      if (skipped) {
        res.statusCode = 404;
        res.end(JSON.stringify({ code: 'error', message: 'not found' }));
        return;
      }

      res.statusCode = 200;
      res.end(JSON.stringify({ fqnAttributeValues }));
      return;
    } else if (url.pathname === '/stop' && req.method === 'GET') {
      server.close(() => {
        console.log('Server gracefully terminated.');
      });
      res.statusCode = 200;
      res.end('Server stopped');
      return;
    } else if (
      url.pathname === '/policy.kasregistry.KeyAccessServerRegistryService/ListKeyAccessServers'
    ) {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({ keyAccessServers: [{ uri: 'http://localhost:3000' }], pagination: {} })
      );
      return;
    } else if (
      url.pathname === '/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration'
    ) {
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(
        JSON.stringify({
          configuration: {
            base_key: {
              kas_id: '34f2acdc-3d9c-4e92-80b6-90fe4dc9afcb',
              kas_uri: 'http://localhost:3000',
              public_key: {
                algorithm: 'ec:secp256r1',
                kid: 'e1',
                pem: Mocks.kasECCert,
              },
            },
          },
        })
      );
      return;
    } else if (url.pathname === '/policy.attributes.AttributesService/ListAttributes') {
      const token = req.headers['authorization'] as string;
      if (!token || !token.startsWith('Bearer dummy-auth-token')) {
        res.statusCode = 401;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ status: 'error' }));
        return;
      }
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ status: 'ok' }));
      return;
    } else {
      console.log(`[DEBUG] invalid path [${url.pathname}]`);
      res.statusCode = 404;
      res.end('Not Found');
    }
  } catch (e) {
    console.error('[ERROR]', e);
    res.statusCode = 500;
    res.end('ERROR');
  }
};

const server = createServer(kas);

server.listen(3000, 'localhost', () => {
  console.log('Server running with disabled CORS at http://localhost:3000/');
});
