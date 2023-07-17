# An OpenTDF Library for Browsers and NodeJS Clients

This project packages a set of javascript modules that can write and read
a variety of OpenTDF data formats, including NanoTDF, Dataset TDF, and the
TDF3 with JSON envelopes.

## Usage

### NanoTDF
```typescript
  const oidcCredentials: RefreshTokenCredentials = {
    clientId: keycloakClientId,
    exchange: 'refresh',
    refreshToken: refreshToken,
    oidcOrigin: keycloakUrl,
  }
  const authProvider = await AuthProviders.refreshAuthProvider(oidcCredentials);
  const client = new NanoTDFClient(authProvider, access);
  const cipherText = await client.encrypt(plainText);
  const clearText = await client.decrypt(cipherText);
```

### TDF3

```typescript
  const client = new TDF3Client({
    clientId: "tdf-client",
    kasEndpoint: 'http://localhost/kas',
    refreshToken: 'token', // Here is only difference in usage, browser build needs oidc tocken
    oidcOrigin: 'http://localhost/oidc',
  });
  const source = new ReadableStream({
    pull(controller) {
      controller.enqueue(new TextEncoder().encode(string));
      controller.close();
    },
  });
  const ciphertextStream = await client.encrypt({ offline: true, source });
  // Optionally: Save ciphertextStream to file or remote here.
  // For demo purposes, we pipe to decrypt.
  const plaintextStream = await client.decrypt({
    source: { type: 'stream', location: ciphertextStream }
  });
  const plaintext = await plaintextStream.toString(); // could be also ct.toFile('img.jpg');
  console.log(`deciphered text :${plaintext}`);
```

## Examples

Review examples to see how to integrate. See [Examples](https://github.com/opentdf/opentdf/tree/main/examples)
