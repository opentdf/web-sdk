# OpenTDF SDK for Browser Applications

This project presents client code to write and read OpenTDF data formats.

## Usage

```typescript
import { AuthProviders, OpenTDF } from '@opentdf/sdk';

// Use refreshAuthProvider for browser applications.
// The refresh token is obtained after the user logs in via your OIDC provider.
const authProvider = await AuthProviders.refreshAuthProvider({
  clientId: 'my-client-id',
  refreshToken: refreshToken,
  oidcOrigin: 'https://keycloak.example.com/auth/realms/my-realm',
});

const client = new OpenTDF({
  authProvider,
  platformUrl: 'https://platform.example.com',
});

// Encrypt
const cipherText = await client.createTDF({
  source: { type: 'buffer', location: new TextEncoder().encode('hello, world') },
  defaultKASEndpoint: 'https://platform.example.com/kas',
});

// Decrypt
const encrypted = new Uint8Array(await new Response(cipherText).arrayBuffer());
const plainText = await client.read({
  source: { type: 'buffer', location: encrypted },
});
console.log(await new Response(plainText).text()); // "hello, world"
```
