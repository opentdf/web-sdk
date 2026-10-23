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

## Validate an existing TDF

Use `isValidTdf` before storing or forwarding a TDF. It opens the archive, reads the
manifest, and validates it against the lax manifest schema from the Go SDK, including
support for experimental `mlkem-wrapped` key access. It accepts a `Uint8Array` or a
`Blob`, such as a browser `File` (Blobs work in Node too), and returns a boolean. Pass
a `File` or `Blob` directly: only the end of the archive, its central directory and
the manifest are read, not the whole file.

```typescript
import { isValidTdf } from '@opentdf/sdk';

if (!(await isValidTdf(file))) {
  throw new Error('Invalid TDF');
}
```

To find out why a TDF was rejected, use `validateTdf`. It resolves to
`{ valid: true }` or `{ valid: false, reason }`. The reason is meant for logs and
diagnostics; its wording may change.

```typescript
import { validateTdf } from '@opentdf/sdk';

const result = await validateTdf(file);
if (!result.valid) {
  console.warn(`Rejected TDF: ${result.reason}`);
}
```

Validation does not initialize a client or contact KAS. It does not check the
referenced payload's existence, length, checksums, or cryptographic integrity.
A successful result does not establish decryptability, authorization, or compliance
with a service's policy requirements.

Invalid archives or manifests resolve as invalid. A source that is neither a
`Uint8Array` nor a `Blob` rejects with a `ConfigurationError`. Other unexpected errors,
including source read failures, also reject the promise. The schema validator is only
loaded the first time it is needed.

This is not full parity with the Go SDK's `IsValidTdf`. The manifest entry names and
which entry wins when a name is repeated (the last one) match, and so does the schema
apart from `mlkem-wrapped`. Otherwise it differs, in both directions. Unlike Go,
`isValidTdf` accepts `mlkem-wrapped` key access, an archive with a ZIP comment, and
deeply nested manifest JSON. It rejects some archives that Go accepts: trailing data
after the manifest JSON, compressed entries or entries whose compressed and
uncompressed sizes differ, and an end of central directory record that overstates the
central directory size.
