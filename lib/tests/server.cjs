const http = require('node:http');

const kid = 'kid-a';
const pem = `
-----BEGIN CERTIFICATE-----
MIIFnjCCA4YCCQCnKw0cfbMLJTANBgkqhkiG9w0BAQsFADCBkDELMAkGA1UEBhMC
VUExCzAJBgNVBAgMAk9EMQ4wDAYDVQQHDAVPREVTQTEPMA0GA1UECgwGVklSVFJV
MREwDwYDVQQLDAhQTEFURk9STTEZMBcGA1UEAwwQbG9jYWwudmlydHJ1LmNvbTEl
MCMGCSqGSIb3DQEJARYWc2l2YW5vdi5jdHJAdmlydHJ1LmNvbTAeFw0yMzA3MDYx
MTUxMzFaFw0yNDA3MDUxMTUxMzFaMIGQMQswCQYDVQQGEwJVQTELMAkGA1UECAwC
T0QxDjAMBgNVBAcMBU9ERVNBMQ8wDQYDVQQKDAZWSVJUUlUxETAPBgNVBAsMCFBM
QVRGT1JNMRkwFwYDVQQDDBBsb2NhbC52aXJ0cnUuY29tMSUwIwYJKoZIhvcNAQkB
FhZzaXZhbm92LmN0ckB2aXJ0cnUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEAn+CvhpQZ6lPZG8j07l8JWWQnmPATKB2GDbcyC/Yg1rJAcFLZmBvH
VR3SamYQrSKxFRsoBGVruIFQBpoYMSolRWVVRnRBmpB5O8vCdP8J78mRaXGoJAez
xexuZBEoUIJJAn0Uoxg462201RgzLrZq+b+gOHZzcOfMlh/HPWhTeLdW2i0oMddL
yeykUa8ARHeCbA1Ux/IZju9n+lY3Pv7pI7z0mYuU14p33lvQbTZ1psY4frwFeyqC
rqHR1NqKjX+CnitFDrVKV48ZNlBQ6y348NpCaNH0wmy4FRAuGS6dJb9KFK6C+KIj
EQlWaucPTgvf6/dgZ6IZdLPvHUQNwC9yidRpnyLTUZlxwCXVO3P1sP7ifq75RwFk
OhvGqnoWNxUwd+23YUOFhE5b7WSO8NwRiMPBeEhNiWaiCmu1v88h52mgRr74MjCQ
mftuJlPwhsqWMpdYuv42851Y95x5s7BFWtntBNcU/+TTSKcygPNGkuR/tNw79JrM
bMl/Wj+cJoCW/3+1KzmPX13Nf2Cq2KZ8Kx6JCy+zFj/Hu8O/iqZ1vxA7gUyESPrd
NFB988QD7H8AQLCeDh6mOTdK08ZG74FlRBSk788A4oyslx8DslOkWbqHLdA7frv6
rEtl3mJ9UchFVpJOXw5nT3plE0ZRx4NWRLAG2+8GIUsL6eylpFUfVH8CAwEAATAN
BgkqhkiG9w0BAQsFAAOCAgEAlS3ph3ZcPf90uo0Y0l6Pca5I7ztuq6wu6reKAqnz
kh6N1rpLSe6EdRIOOCkMWMYTlZYFnSG/USGRfiCV0TOoo2C+jFvARRn6oir1v3B4
XBQORRNrOP8xV6kXAmNxs9Zl8CpAxfejV0vBHzN709q2HDfwmMmmp/yhlsAa1/iL
ARYV3TIJBmAOpec2CemuSVwGvYF7Ojl4sTYl0qMzrmm85wMBHJWR9EJbbFZBDDi4
GKVx26SfxaeauZXRgbO7Tav0q7mbJXI6u95aWO6iwkABRfnEQbimfVCjRI4TKlNs
WX5PS3QXXJg/9ocEglNGDwTouDwD/yMevR2tJ4clb9SJkJjJ3I0t7aUoFHXBl0B2
merKiN1ZE4OlbG/BsJypwAqV7Xk6tK3LM8fCMxhP1K0XX5Ifi1+hbN4Wr7a/zpEq
RWFMXtPKqTne0Ut6M7Xv5BBjY3uBmp0AX9hXt00olAiZsrOfj4gjAVULxdsbaEpr
nTqI65s26fls4y9bCZSfY//YNMAAtSRfmGbCZfrnzyvMtZfSMHqxhzMX7jXonV9c
TuHue7faEGaGlWGQVdNeudZaQ/eimDWeWnbhoUz6hSX7NICUFE64W6+GVFsAte3s
jtfbjUcLqvZzZt+u7YDapWbEbdgYjn/lUt0sTNyY65IagXJel9iacjCIVdzoKPzn
HJg=
-----END CERTIFICATE-----
`.trim();

function range(start, end) {
  const result = [];
  for (let i = start; i <= end; i++) {
    result.push(i);
  }
  return new Uint8Array(result);
}

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Range');
  const url = new URL(req.url, `http://${req?.headers?.host}`);
  if (url.pathname === '/file' && req.method === 'GET') {
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
        rangeData = fullRange.slice(rangeStart)
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
  } else if (url.pathname === '/kas_public_key' && req.method === 'GET') {
    const algorithm = url.searchParams.get('algorithm') || 'rsa:2048';
    if (!['ec:secp256r1', 'rsa:2048'].includes(algorithm)) {
      res.writeHead(400);
      res.end();
      return;
    }
    const fmt = url.searchParams.get('fmt') || 'pkcs8';
    if (!['jwks', 'pkcs8'].includes(fmt)) {
      res.writeHead(400);
      res.end();
      return;
    }
    const v2 = '2' == url.searchParams.get('v');
    res.setHeader('Content-Type', 'application/json');
    res.statusCode = 200;
    res.end(JSON.stringify(v2 ? { kid, pem } : pem));
  } else if (req.method === 'OPTIONS') {
    res.statusCode = 200;
    res.end();
  } else {
    res.statusCode = 404; // Not Found
    res.end('Not Found');
  }
});

server.listen(3000, 'localhost', () => {
  console.log('Server running with disabled CORS at http://localhost:3000/');
});
