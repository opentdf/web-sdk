import * as jose from 'jose';
import { createServer, IncomingMessage, RequestListener, ServerResponse } from 'node:http';

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

import { create, toJsonString, fromJson } from '@bufbuild/protobuf';
import { ValueSchema } from '@bufbuild/protobuf/wkt';
import {
  PolicyRewrapResultSchema,
  KeyAccessRewrapResultSchema,
  RewrapResponseSchema,
  UnsignedRewrapRequestSchema,
} from '../src/platform/kas/kas_pb.js';

const Mocks = getMocks();

// =============================================================================
// DPoP proof verification (RFC 9449 + RFC 7518 §3.4) for the mock server.
// Strict on purpose: this is what real Keycloak / panva-jose do, so when a
// regression in our SDK's proof minting (e.g. DER-encoded ECDSA) lands, the
// integration tests fail locally instead of only at xtest time.
// =============================================================================

const DPOP_TOKEN_NONCE = 'dpop-test-nonce-abc';
const DPOP_RS_NONCE = 'dpop-test-rs-nonce-xyz';
const DPOP_IAT_SKEW_SECONDS = 60;

// access_token → JWK SHA-256 thumbprint of the key it was bound to.
// Populated by the token endpoint when minting a DPoP-bound token; consulted
// by the KAS rewrap handler to enforce RFC 9449 §6.1 jkt binding.
const dpopBoundJkts = new Map<string, string>();

// Seen jti values per minted-by-this-server lifetime to detect replay.
// Real servers would TTL-evict; this is a test mock, full clear on shutdown is fine.
const seenJtis = new Set<string>();

type DPoPCheckOpts = {
  htm: string;
  htu: string;
  requireAth?: { accessToken: string };
  requireBoundJkt?: string;
  requireNonce?: string;
};

type DPoPCheckResult =
  | { ok: true; jkt: string; jti: string; payload: jose.JWTPayload }
  | {
      ok: false;
      status: number;
      error: string;
      error_description: string;
      // If set, the server must include this DPoP-Nonce header so the client retries.
      challengeNonce?: string;
    };

/** Strict-mode parse and verify a DPoP proof per RFC 9449 + RFC 7518 §3.4. */
async function verifyDpopProof(
  rawProof: string | undefined,
  opts: DPoPCheckOpts
): Promise<DPoPCheckResult> {
  if (!rawProof) {
    return {
      ok: false,
      status: 400,
      error: 'invalid_request',
      error_description: 'DPoP header required',
    };
  }

  let protectedHeader: jose.ProtectedHeaderParameters;
  try {
    protectedHeader = jose.decodeProtectedHeader(rawProof);
  } catch (err) {
    return {
      ok: false,
      status: 400,
      error: 'invalid_dpop_proof',
      error_description: `cannot decode DPoP header: ${(err as Error).message}`,
    };
  }
  if (protectedHeader.typ !== 'dpop+jwt') {
    return {
      ok: false,
      status: 400,
      error: 'invalid_dpop_proof',
      error_description: `typ must be "dpop+jwt", got ${String(protectedHeader.typ)}`,
    };
  }
  const alg = protectedHeader.alg;
  if (!alg || alg === 'none' || alg.startsWith('HS') || !/^(ES|RS|PS|EdDSA)/.test(alg)) {
    return {
      ok: false,
      status: 400,
      error: 'invalid_dpop_proof',
      error_description: `alg "${String(alg)}" is not an allowed asymmetric JWS alg`,
    };
  }
  const jwk = protectedHeader.jwk;
  if (!jwk || typeof jwk !== 'object') {
    return {
      ok: false,
      status: 400,
      error: 'invalid_dpop_proof',
      error_description: 'jwk header parameter missing',
    };
  }
  for (const forbidden of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k']) {
    if (forbidden in (jwk as Record<string, unknown>)) {
      return {
        ok: false,
        status: 400,
        error: 'invalid_dpop_proof',
        error_description: `jwk must not contain private parameter "${forbidden}"`,
      };
    }
  }

  let key: jose.CryptoKey | Uint8Array;
  try {
    key = (await jose.importJWK(jwk as jose.JWK, alg)) as jose.CryptoKey;
  } catch (err) {
    return {
      ok: false,
      status: 400,
      error: 'invalid_dpop_proof',
      error_description: `cannot import jwk: ${(err as Error).message}`,
    };
  }

  let payload: jose.JWTPayload;
  try {
    ({ payload } = await jose.jwtVerify(rawProof, key));
  } catch (err) {
    return {
      ok: false,
      status: 400,
      error: 'invalid_dpop_proof',
      error_description: `signature verification failed: ${(err as Error).message}`,
    };
  }

  if (payload.htm !== opts.htm) {
    return {
      ok: false,
      status: 400,
      error: 'invalid_dpop_proof',
      error_description: `htm mismatch: expected ${opts.htm}, got ${String(payload.htm)}`,
    };
  }
  if (payload.htu !== opts.htu) {
    return {
      ok: false,
      status: 400,
      error: 'invalid_dpop_proof',
      error_description: `htu mismatch: expected ${opts.htu}, got ${String(payload.htu)}`,
    };
  }
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.iat !== 'number' || Math.abs(now - payload.iat) > DPOP_IAT_SKEW_SECONDS) {
    return {
      ok: false,
      status: 400,
      error: 'invalid_dpop_proof',
      error_description: `iat out of window (${String(payload.iat)} vs server now ${now})`,
    };
  }
  if (typeof payload.jti !== 'string' || payload.jti.length === 0) {
    return {
      ok: false,
      status: 400,
      error: 'invalid_dpop_proof',
      error_description: 'jti claim required',
    };
  }
  if (seenJtis.has(payload.jti)) {
    return {
      ok: false,
      status: 400,
      error: 'invalid_dpop_proof',
      error_description: 'jti replay detected',
    };
  }

  if (opts.requireNonce && payload.nonce !== opts.requireNonce) {
    return {
      ok: false,
      status: 0, // caller decides 400 (AS) vs 401 (RS)
      error: 'use_dpop_nonce',
      error_description: 'DPoP nonce required',
      challengeNonce: opts.requireNonce,
    };
  }

  if (opts.requireAth) {
    const expected = await athClaim(opts.requireAth.accessToken);
    if (payload.ath !== expected) {
      return {
        ok: false,
        status: 401,
        error: 'invalid_dpop_proof',
        error_description: `ath mismatch: expected ${expected}, got ${String(payload.ath)}`,
      };
    }
  }

  const jkt = await jose.calculateJwkThumbprint(jwk as jose.JWK);
  if (opts.requireBoundJkt && opts.requireBoundJkt !== jkt) {
    return {
      ok: false,
      status: 401,
      error: 'invalid_token',
      error_description: 'access token cnf.jkt does not match DPoP proof jkt',
    };
  }

  seenJtis.add(payload.jti);
  return { ok: true, jkt, jti: payload.jti, payload };
}

/** RFC 9449 §6.1: ath = base64url-nopad(SHA-256(ASCII(access_token))). */
async function athClaim(accessToken: string): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(accessToken));
  return base64UrlNoPad(new Uint8Array(hash));
}

function base64UrlNoPad(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/** Build the htu (target URI sans query and fragment) for a server request. */
function requestHtu(req: IncomingMessage): string {
  // The test server listens on http://localhost:3000; URL fields beyond
  // pathname (query, fragment) MUST be stripped per RFC 9449 §4.2.
  const url = new URL(req.url ?? '/', 'http://localhost:3000');
  return `${url.origin}${url.pathname}`;
}

/**
 * RFC 9449 resource-server DPoP gate for Connect-RPC endpoints. A no-op
 * (returns true) unless the request carries `Authorization: DPoP <token>`, so
 * Bearer / unauthenticated callers pass through unchanged and the many non-DPoP
 * tests keep working.
 *
 * On a proof failure it writes a Connect-correct response and returns false; the
 * caller MUST `return` immediately. The status is always 401 so connect-web maps
 * it to Code.Unauthenticated (HTTP 400 would map to Code.Internal, which the
 * SDK's nonce-retry interceptor does not act on). The nonce travels in the
 * `DPoP-Nonce` response header (surfaced to the client via ConnectError.metadata),
 * and the JSON body uses the Connect `{code, message}` envelope.
 *
 * The proof's `htm` is always 'POST': both SDK interceptors hard-code POST when
 * minting the proof regardless of the verb the Connect transport uses, so we must
 * NOT derive htm from req.method here.
 */
async function enforceRsDpop(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  const authHeader = (req.headers['authorization'] as string | undefined) ?? '';
  const dpopMatch = /^DPoP\s+(.+)$/.exec(authHeader);
  if (!dpopMatch) return true; // non-DPoP request → unchanged behavior

  const accessToken = dpopMatch[1];
  const proofCheck = await verifyDpopProof(req.headers['dpop'] as string | undefined, {
    htm: 'POST',
    htu: requestHtu(req),
    requireAth: { accessToken },
    requireBoundJkt: dpopBoundJkts.get(accessToken),
    requireNonce: DPOP_RS_NONCE,
  });
  if (proofCheck.ok) return true;

  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (proofCheck.challengeNonce) {
    headers['DPoP-Nonce'] = proofCheck.challengeNonce;
    headers['WWW-Authenticate'] = `DPoP error="${proofCheck.error}"`;
  }
  res.writeHead(401, headers);
  res.end(
    JSON.stringify({
      code: 'unauthenticated',
      message: proofCheck.error_description || proofCheck.error,
    })
  );
  return false;
}

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
      'x-virtrupubkey',
    ].join(', ')
  );
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Expose-Headers', 'DPoP-Nonce');
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

      // Strict RFC 9449 DPoP resource-server check. Only triggers when the
      // request actually carries `Authorization: DPoP <token>`; non-DPoP
      // (Bearer or unauthenticated) callers pass through unchanged so the
      // many non-DPoP rewrap tests keep working.
      if (!(await enforceRsDpop(req, res))) return;

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
        if (clientPublicKey.algorithm.name == 'RSA-OAEP') {
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
        const kek = await keyAgreement(sessionKeyPair.privateKey, clientPublicKey, {
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
      // DPoP callers are authenticated by the RS gate; Bearer callers fall
      // through to the legacy `Bearer dummy-auth-token` check below.
      if (!(await enforceRsDpop(req, res))) return;
      res.setHeader('Content-Type', 'application/json');
      const token = req.headers['authorization'] as string;
      if (!token || !(token.startsWith('Bearer dummy-auth-token') || token.startsWith('DPoP '))) {
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
      if (!(await enforceRsDpop(req, res))) return;
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
      // DPoP callers are authenticated by the RS gate; Bearer callers fall
      // through to the legacy `Bearer dummy-auth-token` check below.
      if (!(await enforceRsDpop(req, res))) return;
      const token = req.headers['authorization'] as string;
      if (!token || !(token.startsWith('Bearer dummy-auth-token') || token.startsWith('DPoP '))) {
        res.statusCode = 401;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ status: 'error' }));
        return;
      }
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ status: 'ok' }));
      return;
    } else if (url.pathname === '/protocol/openid-connect/token') {
      // Mock Keycloak token endpoint with strict RFC 9449 DPoP verification.
      // First request gets a nonce challenge (400 + use_dpop_nonce + DPoP-Nonce header
      // per RFC 9449 §8 — note: AS uses 400, RS uses 401). The retry must include
      // a proof whose `nonce` claim matches.
      const dpopHeader = req.headers['dpop'] as string | undefined;
      const htu = requestHtu(req);
      const check = await verifyDpopProof(dpopHeader, {
        htm: 'POST',
        htu,
        requireNonce: DPOP_TOKEN_NONCE,
      });
      if (!check.ok) {
        const status =
          check.error === 'use_dpop_nonce' ? 400 : check.status > 0 ? check.status : 400;
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (check.challengeNonce) headers['DPoP-Nonce'] = check.challengeNonce;
        res.writeHead(status, headers);
        res.end(JSON.stringify({ error: check.error, error_description: check.error_description }));
        return;
      }

      // Mint an opaque access token; bind it to the DPoP proof's JWK thumbprint
      // so the rewrap handler (RS-side, below) can enforce cnf.jkt binding.
      const accessToken = 'test-dpop-token';
      dpopBoundJkts.set(accessToken, check.jkt);

      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ access_token: accessToken, token_type: 'DPoP', expires_in: 3600 }));
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
