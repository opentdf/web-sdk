# An OpenTDF Library for Browser Applications

This project presents client code to write and read a OpenTDF data formats. This included NanoTDF
and collections and Base TDF3.

## Usage

### NanoTDF

```typescript
import { type Chunker, OpenTDF } from '@opentdf/sdk';

const oidcCredentials: RefreshTokenCredentials = {
  clientId: keycloakClientId,
  exchange: 'refresh',
  refreshToken: refreshToken,
  oidcOrigin: keycloakUrl,
};
const authProvider = await AuthProviders.refreshAuthProvider(oidcCredentials);
const client = new OpenTDF({
  authProvider,
  defaultCreateOptions: {
    defaultKASEndpoint: kasEndpoint, // Server used for Key Access Control
  },
  dpopKeys: authProvider.getSigningKey(),
});
const cipherText = await client.createNanoTDF({
  source: { type: 'stream', location: source },
});

const clearText = await client.read({ type: 'stream', location: cipherText });
```

### ZTDF

```typescript
import { type Chunker, OpenTDF } from '@opentdf/sdk';

const oidcCredentials: RefreshTokenCredentials = {
  clientId: keycloakClientId,
  exchange: 'refresh',
  refreshToken: refreshToken,
  oidcOrigin: keycloakUrl,
};
const authProvider = await AuthProviders.refreshAuthProvider(oidcCredentials);
const client = new OpenTDF({
  authProvider,
  defaultCreateOptions: {
    defaultKASEndpoint: kasEndpoint, // Server used for Key Access Control
  },
  dpopKeys: authProvider.getSigningKey(),
});
const cipherText = await client.createZTDF({
  source: { type: 'stream', location: source },
  autoconfigure: false,
});

const clearText = await client.read({ type: 'stream', location: cipherText });
```
