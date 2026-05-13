import * as jose from 'jose';
import { createServer, IncomingMessage, RequestListener } from 'node:http';
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

import { base64 } from '../src/encodings/index.js';
import { decryptWithPrivateKey, encryptWithPublicKey } from '../tdf3/src/crypto/index.js';
import { getMocks } from './mocks/index.js';
import { keyAgreement, pemPublicToCrypto } from '../src/crypto/index.js';
import { generateRandomNumber } from '../src/crypto/generateRandomNumber.js';
import { removePemFormatting } from '../tdf3/src/crypto/crypto-utils.js';
import { Binary } from '../tdf3/index.js';
import { valueFor } from './web/policy/mock-attrs.js';
import { AttributeAndValue } from '../src/policy/attributes.js';
import { getZtdfSalt } from '../tdf3/src/crypto/salt.js';
import { DefaultCryptoService } from '../tdf3/src/crypto/index.js';

// ML-KEM server-side key pairs, generated once at startup.
const KAS_ML_KEM_KEYS = {
  512: ml_kem512.keygen(),
  768: ml_kem768.keygen(),
  1024: ml_kem1024.keygen(),
} as const;

const MLKEM_CT_SIZES: Record<512 | 768 | 1024, number> = { 512: 768, 768: 1088, 1024: 1568 };
const MLKEM_EK_SIZES: Record<number, 512 | 768 | 1024> = { 800: 512, 1184: 768, 1568: 1024 };
const MLKEM_APIS = { 512: ml_kem512, 768: ml_kem768, 1024: ml_kem1024 } as const;

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
      'x-test-required-obligations',
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

      const validAlgorithms = ['ec:secp256r1', 'rsa:2048', 'mlkem:512', 'mlkem:768', 'mlkem:1024'];
      if (!validAlgorithms.includes(algorithm)) {
        console.log(`[DEBUG] invalid algorithm [${algorithm}]`);
        res.writeHead(400);
        res.end(`{"error": "Invalid algorithm [${algorithm}]"}`);
        return;
      }
      if (algorithm.startsWith('mlkem:')) {
        const level = parseInt(algorithm.split(':')[1], 10) as 512 | 768 | 1024;
        const ek = KAS_ML_KEM_KEYS[level].publicKey;
        res.setHeader('Content-Type', 'application/json');
        res.statusCode = 200;
        res.end(JSON.stringify({ kid: `mlkem${level}`, publicKey: base64.encodeArrayBuffer(ek) }));
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
            if (req.headers['x-test-required-obligations']) {
              console.log(
                '[DEBUG] required obligations header found ',
                req.headers['x-test-required-obligations'] as string
              );
              const obligations: string[] = JSON.parse(
                req.headers['x-test-required-obligations'] as string
              );
              console.log('[DEBUG] required obligations: ', obligations);
              const reply = create(RewrapResponseSchema, {
                responses: [
                  create(PolicyRewrapResultSchema, {
                    results: [
                      create(KeyAccessRewrapResultSchema, {
                        metadata: {
                          'X-Required-Obligations': {
                            kind: {
                              case: 'listValue',
                              value: {
                                values: obligations.map((obligation) =>
                                  create(ValueSchema, {
                                    kind: {
                                      case: 'stringValue',
                                      value: obligation,
                                    },
                                  })
                                ),
                              },
                            },
                          },
                        },
                        result: {
                          case: 'error',
                          value: 'Permission denied',
                        },
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

      // ML-KEM public keys are raw base64 bytes; RSA/EC keys arrive as PEM (with -----BEGIN header).
      const clientKeyIsPem = rewrap.clientPublicKey.startsWith('-----');
      let clientKeyRaw: Uint8Array | undefined;
      let clientMlKemLevel: 512 | 768 | 1024 | undefined;
      if (!clientKeyIsPem) {
        clientKeyRaw = new Uint8Array(base64.decodeArrayBuffer(rewrap.clientPublicKey));
        clientMlKemLevel = MLKEM_EK_SIZES[clientKeyRaw.length];
      }
      const isMLKEMClient = clientMlKemLevel !== undefined;

      let clientPublicKey: CryptoKey | undefined;
      if (!isMLKEMClient) {
        clientPublicKey = await pemPublicToCrypto(rewrap.clientPublicKey);
        if (!clientPublicKey || clientPublicKey.type !== 'public') {
          res.writeHead(400);
          res.end('{"error": "Invalid client public key"}');
          return;
        }
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
        const kid = keyAccessObject?.kid || '';
        const isECWrapped = kid == 'e1';
        const isMlKemWrapped = kid === 'mlkem512' || kid === 'mlkem768' || kid === 'mlkem1024';
        // Decrypt the wrapped key from TDF3
        let dek: Binary;
        if (isMlKemWrapped) {
          const kasLevel = parseInt(kid.replace('mlkem', ''), 10) as 512 | 768 | 1024;
          const ctLen = MLKEM_CT_SIZES[kasLevel];
          const kemCt = wk.slice(0, ctLen);
          const iv = wk.slice(ctLen, ctLen + 12);
          const wrappedDek = wk.slice(ctLen + 12);

          const sharedSecret = MLKEM_APIS[kasLevel].decapsulate(
            kemCt,
            KAS_ML_KEM_KEYS[kasLevel].secretKey
          );

          const hkdfKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, [
            'deriveKey',
          ]);
          const salt = await getZtdfSalt(DefaultCryptoService);
          const aesKey = await crypto.subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt, info: new Uint8Array(0) },
            hkdfKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
          );
          const dekAb = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, wrappedDek);
          dek = Binary.fromArrayBuffer(dekAb);
        } else if (isECWrapped) {
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
            hkdfSalt: await getZtdfSalt(DefaultCryptoService),
            hkdfHash: 'SHA-256',
          });
          const iv = wk.slice(0, 12);
          const wrappedKey = wk.slice(12);
          const dekab = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, kek, wrappedKey);
          dek = Binary.fromArrayBuffer(dekab);
        } else {
          dek = await decryptWithPrivateKey(Binary.fromArrayBuffer(wk), Mocks.kasPrivateKey);
        }
        if (isMLKEMClient && clientMlKemLevel !== undefined && clientKeyRaw !== undefined) {
          const { cipherText, sharedSecret } =
            MLKEM_APIS[clientMlKemLevel].encapsulate(clientKeyRaw);
          const hkdfKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, [
            'deriveKey',
          ]);
          const salt = await getZtdfSalt(DefaultCryptoService);
          const newAesKey = await crypto.subtle.deriveKey(
            { name: 'HKDF', hash: 'SHA-256', salt, info: new Uint8Array(0) },
            hkdfKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
          );
          const iv = generateRandomNumber(12);
          const aesCt = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            newAesKey,
            dek.asArrayBuffer()
          );
          const entityWrappedKey = concat([cipherText, iv, new Uint8Array(aesCt)]);
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
        } else if (clientPublicKey!.algorithm.name == 'RSA-OAEP') {
          // Import the client public key as opaque PublicKey for encryptWithPublicKey
          const clientPubKeyOpaque = await DefaultCryptoService.importPublicKey(
            rewrap.clientPublicKey,
            { usage: 'encrypt' }
          );
          const cek = await encryptWithPublicKey(dek, clientPubKeyOpaque);
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
        const kek = await keyAgreement(sessionKeyPair.privateKey, clientPublicKey!, {
          hkdfSalt: await getZtdfSalt(DefaultCryptoService),
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
      // Unsupported format (non-ZTDF)
      res.writeHead(400);
      res.end('{"error": "Unsupported TDF format"}');
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
