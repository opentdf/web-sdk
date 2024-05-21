# OpenTDF Web Browser Client opentdf

This project is focused on providing web client support for the OpenTDF family of data protection formats and protocols. Notably, it is a web-friendly library `@opentdf/client`, and tools and support for testing it and building it into web applications.

## Evaluate

Do you want a quick demonstration of OpenTDF? See [Quickstart](https://github.com/opentdf/opentdf/tree/main/quickstart#readme)

## Integrate

Ready to begin integrating into your system?  
Start a local, blank cluster. See [Integrate](https://github.com/opentdf/opentdf/tree/main/quickstart#readme)

### Usage

```typescript
  // currently we support only ESM import
  import { AuthProviders, NanoTDFClient } from '@opentdf/client';

  const oidcCredentials: RefreshTokenCredentials = {
    clientId: keycloakClientId,
    exchange: 'refresh',
    refreshToken: refreshToken,
    oidcOrigin: keycloakUrlWithRealm,
  }
  const authProvider = await AuthProviders.refreshAuthProvider(oidcCredentials);
  const client = new NanoTDFClient(authProvider, access);
  const cipherText = await client.encrypt(plainText);
  const clearText = await client.decrypt(cipherText);
```

## Distribute

```shell
make dist
```

## Contribute

### Prerequisites

Developing with this code requires a recent version of `npm` and `node`.

- Install [nvm](https://github.com/nvm-sh/nvm#readme)
  - see https://github.com/nvm-sh/nvm#installing-and-updating
  - `nvm use` will install `npm` and `node`

[![Build](https://github.com/opentdf/client-web/actions/workflows/build.yaml/badge.svg)](https://github.com/opentdf/client-web/actions/workflows/build.yaml)

To check out, build, and validate your installation, and test the sample web application, you may:

```sh
nvm use
make test
make start
```
