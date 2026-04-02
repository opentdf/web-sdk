# OpenTDF Web Browser Client opentdf

This project is focused on providing web client support for the OpenTDF platform.
This includes encrypting and decrypting TDF content,
and some management tasks for ABAC.

**[OpenTDF Web Documentation](https://opentdf.github.io/web-sdk/)**

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
  source: { type: 'stream', location: plainTextStream },
  autoconfigure: false,
  defaultKASEndpoint: 'https://platform.example.com/kas',
});

// Decrypt
const reader = client.open({ source: { type: 'stream', location: cipherText } });
const clearText = await reader.decrypt();
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
import { type Interceptor, OpenTDF } from '@opentdf/sdk';

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

### With AuthProvider (Deprecated)

The `AuthProvider` pattern is still supported for backwards compatibility but is deprecated since 0.14.0.

```typescript
import { AuthProviders, OpenTDF } from '@opentdf/sdk';

const authProvider = await AuthProviders.refreshAuthProvider({
  clientId: 'applicationNameFromIdP',
  exchange: 'refresh',
  refreshToken: 'refreshToken',
  oidcOrigin: 'http://localhost:65432/auth/realms/opentdf',
});

const client = new OpenTDF({
  authProvider,
  defaultCreateOptions: {
    defaultKASEndpoint: 'http://localhost:65432/kas',
  },
});
```

You can bridge an existing `AuthProvider` to the interceptor pattern using `authProviderInterceptor`:

```typescript
import { AuthProviders, authProviderInterceptor, OpenTDF } from '@opentdf/sdk';

const authProvider = await AuthProviders.clientSecretAuthProvider({
  clientId: 'myClient',
  clientSecret: 'mySecret',
  oidcOrigin: 'http://localhost:65432/auth/realms/opentdf',
  exchange: 'client',
});

const client = new OpenTDF({
  interceptors: [authProviderInterceptor(authProvider)],
  platformUrl: 'https://platform.example.com',
});
```

## Platform Client

The Platform Client provides an interface to interact with the OpenTDF platform's RPC services.

```typescript
import { authTokenInterceptor } from '@opentdf/sdk';
import { PlatformClient } from '@opentdf/sdk/platform';

const platform = new PlatformClient({
  interceptors: [authTokenInterceptor(() => myAuth.getAccessToken())],
  platformUrl: 'https://platform.example.com',
});

// Fetch well-known configuration
const wellKnownResponse = await platform.v1.wellknown.getWellKnownConfiguration({});
console.log('Well-known configuration:', wellKnownResponse.configuration);

// List policy attributes
const attributesResponse = await platform.v1.attributes.listAttributes({});
console.log('Policy Attributes:', attributesResponse.attributes);
```


## Building and Testing

### Makefile Commands

The project provides a `Makefile` to simplify common development tasks. Below are the available commands:

| Command           | Description                                                                                  |
|-------------------|----------------------------------------------------------------------------------------------|
| `make`            | Builds and tests everything (default target).                                                |
| `make start`      | Builds all packages and starts the web application in development mode.                      |
| `make ci`         | Installs dependencies and links the SDK package for all subprojects.                         |
| `make i`          | Installs dependencies and links the SDK package for all subprojects (without clean install). |
| `make clean`      | Removes build artifacts, packed files, and `node_modules` directories.                       |
| `make cli`        | Builds and packs the CLI tool.                                                               |
| `make audit`      | Runs `npm audit` for all packages except dev dependencies.                                   |
| `make format`     | Runs code formatting for all packages.                                                       |
| `make lint`       | Runs linter for all packages.                                                                |
| `make test`       | Runs tests for all packages.                                                                 |
| `make license-check` | Checks license compliance for all packages.                                               |
| `make doc`        | Generates documentation for the SDK.                                                         |
| `make generate-platform` | Runs the platform code generation script.                                             |
| `make dist`       | Copies the SDK package to the root directory.                                                |

You can run any of these commands using `make <command>`.


## Contribute

### Prerequisites

Developing with this code requires a recent version of `npm` and `node`.
We develop using [nvm](https://github.com/nvm-sh/nvm#readme),
which allows us to pin to the same version of `npm` easily.

- Install [nvm](https://github.com/nvm-sh/nvm#readme)
  - see <https://github.com/nvm-sh/nvm#installing-and-updating>
  - `nvm use` will install `npm` and `node`

[![Build](https://github.com/opentdf/web-sdk/actions/workflows/build.yaml/badge.svg)](https://github.com/opentdf/web-sdk/actions/workflows/build.yaml)

To check out, build, and validate your installation, and test the sample web application, you may:

```sh
nvm use
make test
make start
```