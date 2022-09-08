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
  }
  const authProvider = await AuthProviders.refreshAuthProvider(oidcCredentials);
  const client = new NanoTDFClient(authProvider, access);
  const cipherText = await client.encrypt(plainText);
  const clearText = await client.decrypt(cipherText);
```

### Examples

Review examples to see how to integrate. See [Examples](https://github.com/opentdf/opentdf/tree/main/examples)

### Simple 2 steps if you wanna install @opentdf/client package locally for development

1. Run and input your password cause command requires access for instaling it as globall package

```
npm run updateLink
```

2. Go to project you want to install package and run 
```
npm link @opentdf/client
```
