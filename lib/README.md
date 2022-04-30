# An OpenTDF Library for Browsers and NodeJS Clients

This project packages a set of javascript modules that can write and read
a variety of OpenTDF data formats, including NanoTDF, Dataset TDF, and the
TDF3 with JSON envelopes.

### Usage

```typescript
  const oidcCredentials: RefreshTokenCredentials = {
    clientId: keycloakClientId,
    exchange: 'refresh',
    oidcRefreshToken: refreshToken,
    oidcOrigin: keycloakUrl,
    organizationName: keycloakRealm
  }
  const authProvider = await AuthProviders.refreshAuthProvider(oidcCredentials);
  const client = new NanoTDFClient(authProvider, access);
  const cipherText = await client.encrypt(plainText);
  const clearText = await client.decrypt(cipherText);
```

### Examples

Review examples to see how to integrate. See [Examples](https://github.com/opentdf/documentation/tree/feature/integrate/examples)
