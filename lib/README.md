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

Resource DPoP proofs default to `dpopMode: 'auto'`. The SDK checks each server's unauthenticated
well-known configuration, then protected resource metadata, for RFC 9449 support. Servers that
advertise it receive the full request URL as `htu`. Everything else receives the bare RPC procedure
path (for example `/kas.AccessService/Rewrap`, with any proxy prefix dropped) that older KAS
releases expect. That includes servers where discovery fails or is blocked, for example by CORS.
This fallback is deliberate, so new clients keep working against older platforms. If the well-known
configuration gives no answer, discovery is retried after 30 seconds; otherwise the answer is cached
for 5 minutes.

Legacy-form proofs do not name the server origin. Deployments where every server supports RFC 9449
should pass `dpopMode: 'rfc9449'` to `authTokenDPoPInterceptor` (or to the OIDC provider
credentials), which skips discovery and always binds proofs to the full URL. `dpopMode: 'legacy'`
always uses the procedure path. The CLI exposes the same setting as `--dpop-mode`.

Before this release, `authTokenDPoPInterceptor` always used the full URL. To keep that behavior,
pass `dpopMode: 'rfc9449'`.

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

## Validate an existing TDF

Use `isValidTdf` before storing or forwarding a TDF. Like the Go SDK's
`IsValidTdf`, it opens the archive, reads the manifest, and validates it against the
lax manifest schema. It accepts a `Uint8Array` or browser `Blob` and returns
a boolean, including support for experimental `mlkem-wrapped` key access:

```typescript
import { isValidTdf } from '@opentdf/sdk';

if (!(await isValidTdf(new Uint8Array(await file.arrayBuffer())))) {
  throw new Error('Invalid TDF');
}
```

Validation does not initialize a client or contact KAS. It does not check the
referenced payload's existence, length, checksums, or cryptographic integrity.
A successful result does not establish decryptability, authorization, or compliance
with a service's policy requirements.

Invalid archives or manifests return `false`. Unexpected errors, including source
read failures, reject the promise. Schema validation loads only when called.
