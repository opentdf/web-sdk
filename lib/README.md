# OpenTDF SDK for Browser Applications

This project presents client code to write and read OpenTDF data formats.

## Usage

### With Interceptors (Recommended)

Use interceptors to provide authentication. The SDK does not manage tokens — you bring your own auth.

```typescript
import { authTokenInterceptor, OpenTDF } from '@opentdf/sdk';

const client = new OpenTDF({
  interceptors: [authTokenInterceptor(() => myAuth.getAccessToken())],
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

The `authTokenInterceptor` takes a function that returns an access token. Your auth library handles token refresh, caching, etc.

For DPoP-bound tokens, use `authTokenDPoPInterceptor`:

```typescript
import { authTokenDPoPInterceptor, OpenTDF } from '@opentdf/sdk';

const dpopInterceptor = authTokenDPoPInterceptor({
  tokenProvider: () => myAuth.getAccessToken(),
});

const client = new OpenTDF({
  interceptors: [dpopInterceptor],
  dpopKeys: dpopInterceptor.dpopKeys,
  platformUrl: 'https://platform.example.com',
});
```

You can also write your own interceptor for full control over request headers:

```typescript
import { type Interceptor } from '@connectrpc/connect';

const myInterceptor: Interceptor = (next) => async (req) => {
  req.header.set('Authorization', `Bearer ${await getToken()}`);
  req.header.set('X-Custom-Header', 'value');
  return next(req);
};

const client = new OpenTDF({
  interceptors: [myInterceptor],
  platformUrl: 'https://platform.example.com',
});
```

### With AuthProvider (Legacy)

The `AuthProvider` pattern is still supported for backwards compatibility.

```typescript
import { AuthProviders, OpenTDF } from '@opentdf/sdk';

const authProvider = await AuthProviders.refreshAuthProvider({
  clientId: 'my-client-id',
  refreshToken: refreshToken,
  oidcOrigin: 'https://keycloak.example.com/auth/realms/my-realm',
});

const client = new OpenTDF({
  authProvider,
  platformUrl: 'https://platform.example.com',
});
```

## Validate an existing encrypted TDF

Use `validateTdf` to check an existing encrypted TDF before storing or forwarding it. It accepts a
`Uint8Array` or browser `Blob` and returns the parsed manifest:

```typescript
import { validateTdf } from '@opentdf/sdk';

const manifest = await validateTdf(new Uint8Array(await file.arrayBuffer()));
console.log(manifest.payload.mimeType);
```

Validation checks archive bounds, duplicate and overlapping entries, the referenced payload,
encryption and segment declarations, payload length, and the manifest and payload ZIP checksums. It
supports stored ZIP entries with `manifest.json` or the legacy `0.manifest.json` name. It reads the
entire payload in bounded chunks; the manifest is decoded in memory. It does not initialize a client
or contact KAS.

ZIP checksums detect accidental corruption, not tampering. A successful result is not proof of
decryptability, cryptographic integrity, authorization, or compliance with a service's policy
requirements. Those checks remain with decryption and the receiving service.
