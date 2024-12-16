import * as jose from 'jose';
import { createServer, IncomingMessage, RequestListener } from 'node:http';

import { base64 } from '../src/encodings/index.js';
import { decryptWithPrivateKey, encryptWithPublicKey } from '../tdf3/src/crypto/index.js';
import { getMocks } from './mocks/index.js';
import { getHkdfSalt, Header } from '../src/nanotdf/index.js';
import { keyAgreement, pemPublicToCrypto } from '../src/nanotdf-crypto/index.js';
import generateRandomNumber from '../src/nanotdf-crypto/generateRandomNumber.js';
import { removePemFormatting } from '../tdf3/src/crypto/crypto-utils.js';
import { Binary } from '../tdf3/index.js';
import { type KeyAccessObject } from '../tdf3/src/models/index.js';
import { valueFor } from './web/policy/mock-attrs.js';
import { AttributeAndValue } from '../src/policy/attributes.js';

const Mocks = getMocks();

function range(start: number, end: number): Uint8Array {
  const result = [];
  for (let i = start; i <= end; i++) {
    result.push(i);
  }
  return new Uint8Array(result);
}

type RewrapBody = {
  algorithm: 'RS256' | 'ec:secp256r1';
  keyAccess: KeyAccessObject & {
    header?: string;
  };
  policy: string;
  clientPublicKey: string;
  // testing only
  invalidKey: string;
  invalidField: string;
};

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
    'authorization, content-type, dpop, range, virtru-ntdf-version, x-test-response, x-test-response-message'
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
    } else if (url.pathname === '/kas_public_key' || url.pathname === '/v2/kas_public_key') {
      const v =
        url.pathname === '/v2/kas_public_key'
          ? url.searchParams.get('v')
            ? url.searchParams.get('v')
            : '2'
          : '1';
      if (req.method !== 'GET') {
        console.log('[DEBUG] invalid method');
        res.statusCode = 405;
        res.end(`{"error": "Invalid method [${req.method}]"}`);
      }
      const algorithm = url.searchParams.get('algorithm') || 'rsa:2048';
      if (!['ec:secp256r1', 'rsa:2048'].includes(algorithm)) {
        console.log(`[DEBUG] invalid algorithm [${algorithm}]`);
        res.writeHead(404);
        res.end(`{"error": "Invalid algorithm [${algorithm}]"}`);
        return;
      }
      const fmt = url.searchParams.get('fmt') || 'pkcs8';
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
      res.end(JSON.stringify(v == '2' ? { kid, publicKey } : publicKey));
    } else if (url.pathname === '/v2/rewrap') {
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
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }
      const body = await getBody(req);
      const bodyText = new TextDecoder().decode(body);
      const { signedRequestToken } = JSON.parse(bodyText);
      // NOTE: Real KAS will verify JWT here
      const { requestBody } = jose.decodeJwt(signedRequestToken);
      const rewrap = JSON.parse(requestBody as string) as RewrapBody;
      switch (rewrap?.algorithm) {
        case 'RS256': {
          // Decrypt the wrapped key from TDF3
          console.log('[INFO]: rewrap request body: ', rewrap);
          const dek = await decryptWithPrivateKey(
            Binary.fromArrayBuffer(base64.decodeArrayBuffer(rewrap.keyAccess.wrappedKey || '')),
            Mocks.kasPrivateKey
          );
          const cek = await encryptWithPublicKey(dek, rewrap.clientPublicKey);
          const reply = {
            entityWrappedKey: base64.encodeArrayBuffer(cek.asArrayBuffer()),
            metadata: { hello: 'world' },
          };
          res.writeHead(200);
          res.end(JSON.stringify(reply));
          return;
        }
        case 'ec:secp256r1': {
          console.log('[INFO] nano rewrap request body: ', rewrap);
          const { header } = Header.parse(
            new Uint8Array(base64.decodeArrayBuffer(rewrap?.keyAccess?.header || ''))
          );
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

          const clientPublicKey = await pemPublicToCrypto(rewrap.clientPublicKey);
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
          const reply = {
            entityWrappedKey: base64.encodeArrayBuffer(entityWrappedKey),
            sessionPublicKey: Mocks.kasECCert,
            metadata: { hello: 'people of earth' },
          };
          res.writeHead(200);
          res.end(JSON.stringify(reply));
          return;
        }
        default:
          console.log(`[DEBUG] invalid rewrap algorithm [${JSON.stringify(rewrap)}]`);
          res.writeHead(400);
          res.end(`{"error": "Invalid algorithm [${rewrap?.algorithm}]"}`);
          return;
      }
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
    } else if (url.pathname === '/attributes/*/fqn') {
      const fqnAttributeValues: Record<string, AttributeAndValue> = {};
      let skipped = 0;
      for (const [k, v] of url.searchParams.entries()) {
        if (k !== 'fqns') {
          continue;
        }
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
      if (skipped) {
        res.statusCode = 404;
        res.end('Not Found');
        return;
      }
      res.writeHead(200);
      res.end(JSON.stringify({ fqnAttributeValues }));
    } else if (url.pathname === '/stop' && req.method === 'GET') {
      server.close(() => {
        console.log('Server gracefully terminated.');
      });
      res.statusCode = 200;
      res.end('Server stopped');
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
