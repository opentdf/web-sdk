# An OpenTDF Library for Browser Applications

This project presents client code to write and read a OpenTDF data formats.
This included NanoTDF, Dataset TDF, and ZTDF.

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
  const client = new NanoTDFClient({authProvider, kasEndpoint});
  const cipherText = await client.encrypt(plainText);
  const clearText = await client.decrypt(cipherText);
```

### ZTDF

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

## Upgrading from 1.x

- The 'RemoteStorage' features have been moved into a separate library, @opentdf/remote-storage.
- We have replaced all usages of node's `Buffer` with the web-friendlier `UInt8Array`.
  You will most likely see this in the return types of some functions.
