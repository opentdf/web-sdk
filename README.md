# OpenTDF Web Browser Client opentdf

This project is focused on providing web client support for the OpenTDF platform.
This includes encrypting and decrypting TDF content,
and some management tasks for ABAC.

**[OpenTDF Web Documentation](https://opentdf.github.io/web-sdk/)**

## Usage (NanoTDF)

```typescript
import { AuthProviders, NanoTDFClient } from '@opentdf/sdk';

// Configuration Options
const kasEndpoint = "http://localhost:65432/kas";

// Authentication options (vary by middleware)
const oidcOrigin = "http://localhost:65432/auth/realms/opentdf";
const clientId = "applicationNameFromIdP";
const refreshToken = "refreshTokenValueFromIdP";

// AuthProviders are middlewares that add `Authorization` or other bearer tokens to requests.
// These include The `refresh` provider can be handed a refresh and optional access token.
const authProvider = await AuthProviders.refreshAuthProvider({
  clientId,
  exchange: 'refresh',
  refreshToken,
  oidcOrigin,
});

const client = new NanoTDFClient({
  authProvider,
  kasEndpoint,
});
client.dataAttributes = ["http://opentdf.io/attr/class/value/secret"]
const cipherText = await client.encrypt(plainText);
const clearText = await client.decrypt(cipherText);
```

### Authorization Middleware Options

#### Client Credentials

For long running server-side apps, a client id + secret is allowed with OAuth2.
This should not be used in a browser, but within a Deno or Node process.

```typescript
import { AuthProviders } from '@opentdf/sdk';

// Authentication options (vary by middleware)
const oidcOrigin = "http://localhost:65432/auth/realms/opentdf";
const clientId = "username";
const clientSecret = "IdP_GENERATED_SECRET";

const authProvider = await AuthProviders.clientSecretAuthProvider({
  clientId,
  clientSecret,
  oidcOrigin,
  exchange: 'client',
});
```

#### Given Credentials

The `refreshAuthProvider` and `externalAuthProvder` allow the application developer to use existing tokens.

```typescript
import { AuthProviders, NanoTDFClient } from '@opentdf/sdk';

const oidcCredentials: RefreshTokenCredentials = {
  clientId: keycloakClientId,
  exchange: 'refresh',
  refreshToken: refreshToken,
  oidcOrigin: keycloakUrlWithRealm,
}
```

#### Building your own provider

A more complete example of using an OIDC compatible provider
with support for authorization code flow with PKCE and DPoP
is available in the [sample `web-app` folder](./web-app/src/session.ts)

## Platform Client

The Platform Client provides an interface to interact with the OpenTDF platform's RPC services.

### Usage Example

Below is an example of how to use the `PlatformClient` to interact with the platform's RPC services.

```typescript
import { AuthProvider, OpenTDF } from '@opentdf/sdk';
import { PlatformClient } from '@opentdf/sdk/platform';

const authProvider: AuthProvider = {/* configure your auth provider */};
const platform = new PlatformClient({
  authProvider,
  platformUrl: '/api',
});

async function exampleUsage() {
  // Fetch well-known configuration
  const wellKnownResponse = await platform.v1.wellknown.getWellKnownConfiguration({});
  console.log('Well-known configuration:', wellKnownResponse.configuration);

  // List policy attributes
  const attributesResponse = await platform.v1.attributes.listAttributes({});
  console.log('Policy Attributes:', attributesResponse.attributes);
}

exampleUsage();
```

### Using Interceptor

The `PlatformClient` client supports the use of interceptors for customizing RPC calls. Interceptors allow you to modify requests or responses, such as adding custom headers or handling authentication, before or after the RPC call is executed.

Below is an example of using an interceptor to add an `Authorization` header to all outgoing requests:

```typescript
import { platformConnect, PlatformClient } from '@opentdf/sdk/platform';

const authInterceptor: platformConnect.Interceptor = (next) => async (req) => {
  req.header.set('Authorization', `Bearer ${accessToken}`);
  return await next(req); // Pass the modified request to the next handler in the chain
};

const platform = new PlatformClient({
  interceptors: [authInterceptor], // Attach the interceptor
  platformUrl: '/api',
});
```

### Key Notes
Interceptors are particularly useful for scenarios where you need to dynamically modify requests, such as adding authentication tokens or logging request/response data.


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