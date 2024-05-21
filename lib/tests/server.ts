import './mocha/setup.js';

import * as jose from 'jose';
import { IncomingMessage, RequestListener, createServer } from 'node:http';

import { base64 } from '../src/encodings/index.js';
import Header from '../src/nanotdf/models/Header.js';
import { pemPublicToCrypto } from '../src/nanotdf-crypto/pemPublicToCrypto.js';
import { Binary } from '../tdf3/index.js';
import { type KeyAccessObject } from '../tdf3/src/models/key-access.js';
import { decryptWithPrivateKey, encryptWithPublicKey } from '../tdf3/src/crypto/index.js';
import getMocks from './mocks/index.js';

const Mocks = getMocks();
const kid = 'kid-a';

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
};

function getBody(request: IncomingMessage): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const bodyParts: Uint8Array[] = [];
    request
      .on('data', (chunk) => {
        bodyParts.push(chunk);
      })
      .on('end', () => {
        resolve(Buffer.concat(bodyParts));
      })
      .on('error', reject);
  });
}

const kas: RequestListener = async (req, res) => {
  console.log('[INFO]: server request: ', req.method, req.url, req.headers);
  res.setHeader('Access-Control-Allow-Headers', 'authorization, content-type, dpop, range, virtru-ntdf-version');
  res.setHeader('Access-Control-Allow-Origin', '*');
  // GET should be allowed for everything except rewrap, POST only for rewrap but IDC
  res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, GET, POST');
  try {
    const url = new URL(req.url || '', `http://${req?.headers?.host}`);
    if (req.method === 'OPTIONS') {
      res.statusCode = 200;
      console.log('[DEBUG] CORS response 200');
      res.end();
    } else if (url.pathname === '/kas_public_key') {
      if (req.method !== 'GET') {
        console.log('[DEBUG] invalid method');
        res.statusCode = 405;
        res.end(`{"error": "Invalid method [${req.method}]"}`);
      }
      const algorithm = url.searchParams.get('algorithm') || 'rsa:2048';
      if (!['ec:secp256r1', 'rsa:2048'].includes(algorithm)) {
        console.log(`[DEBUG] invalid algorithm [${algorithm}]`);
        res.writeHead(400);
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
      const v2 = '2' == url.searchParams.get('v');
      res.setHeader('Content-Type', 'application/json');
      res.statusCode = 200;
      const publicKey = 'ec:secp256r1' == algorithm ? Mocks.kasECCert : Mocks.kasPublicKey;
      res.end(JSON.stringify(v2 ? { kid, publicKey } : publicKey));
    } else if (url.pathname === '/v2/rewrap') {
      if (req.method !== 'POST') {
        console.error(`[ERROR] /v2/rewrap only accepts POST verbs, received [${req.method}]`);
        res.writeHead(405);
        res.end(`{"error": "Invalid method [${req.method}]"}`);
        return;
      }
      console.log('[INFO]: rewrap request meta: ', req.method, req.url, req.headers);
      // NOTE: Real KAS will validate authorization and dpop here.
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
          const { header } = Header.parse(new Uint8Array(base64.decodeArrayBuffer(rewrap?.keyAccess?.header || '')));
          const nanoPublicKey = await pemPublicToCrypto(header.ephemeralPublicKey);
          const clientPublicKey = await pemPublicToCrypto(rewrap.clientPublicKey);
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
        res.end(Buffer.from(rangeData.buffer));
      } else {
        res.statusCode = 200; // OK
        res.setHeader('Content-Type', 'application/octet-stream');
        res.end(Buffer.from(fullRange.buffer));
      }
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
