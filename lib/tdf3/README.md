[![CI Status](https://github.com/opentdf/tdf3-js/actions/workflows/build.yaml/badge.svg)](https://github.com/opentdf/tdf3-js/actions/workflows/build.yaml)

# tdf3-js

A JavaScript client library that can be used to encrypt and decypt files using the TDF3
specification.

## Install & Build

First install all packages required:

`npm ci`

Build:

`npm run build`. The built file can be found in `/build`

Note: If running tests, the build is run automatically.

## Running Tests

1. Download, and run a KAS (Key Access Server): `npm run setup`
1. Start the KAS: `npm start`
1. Build tdf3-js: `npm run build`
1. Then: `npm test`

Note: Step 1 grabs `main` branch of the kas. If you'd like to get a different branch do the
following:

`BRANCH=<branch name> npm run setup.`

To terminate the running kas: `npm stop`

## Example
### node.js

```js
const { TDF3Client } = require("@opentdf/client");

(async function() {
  const client = new TDF3Client({
    clientId: "tdf-client",
    kasEndpoint: 'http://localhost/kas',
    clientSecret: 'someSecret',
    oidcOrigin: 'http://localhost/oidc',
  });
  const source = new ReadableStream({
      pull(controller) {
        controller.enqueue(new TextEncoder().encode(string));
        controller.close();
      },
    });
  const ct = await client.encrypt({
    source,
    offline: true,
  });
  const ciphertext = await ct.toString(); // could be also ct.toFile('img.jpg.html')
  console.log(`ciphered text :${ciphertext}`);

  const decryptParams = new Client.DecryptParamsBuilder()
    .withStringSource(ciphertext) // could be also withFileSource('img.jpg.html')
    .build();
  const plaintextStream = await client.decrypt(decryptParams);
  const plaintext = await plaintextStream.toString(); // could be also ct.toFile('img.jpg');
  console.log(`deciphered text :${plaintext}`);
})();
```

### browser
```js
  const client = new Client.Client({
    clientId: "tdf-client",
    kasEndpoint: 'http://localhost/kas',
    refreshToken: 'token', // Here is only difference in usage, browser build needs oidc tocken
    oidcOrigin: 'http://localhost/oidc',
  });
```
Rest is the same, you could use `withArrayBufferSource` for files in browser. For generating file in browser you could do
```js
  const plainString = await plainStream.toString('base64');
  const a = document.getElementById("download_link");
  a.download = "filenName.html";
  a.href = "data:text/html;charset=utf-8," + encodeURIComponent(plainString);
```

clicking on that line allows you to download the file
