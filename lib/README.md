# An OpenTDF Library for Browser Applications

This project presents client code to write and read OpenTDF data formats (ZTDF).

## Usage

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

// Encrypt
const cipherText = await client.createZTDF({
  source: { type: 'stream', location: source },
  autoconfigure: false,
});

// Decrypt
const reader = client.open({ source: { type: 'stream', location: cipherText } });
const clearText = await reader.decrypt();
```
