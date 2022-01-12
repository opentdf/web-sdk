# openTDF Web Browser Client Documentation

This project is focused on providing web client support for the openTDF family of data protection formats and protocols. Notably, it is a web-friendly library `@opentdf/client`, and tools and support for testing it and building it into web applications.

## Evaluate

Do you want a quick demonstration of openTDF? See [Quickstart](https://github.com/opentdf/documentation/tree/main/quickstart#readme)

## Integrate

Ready to begin integrating into your system?  
Start a local, blank cluster. See [Integrate](https://github.com/opentdf/documentation/tree/main/quickstart#readme)

### Usage

```typescript
  const oidcCredentials: RefreshTokenCredentials = {
    clientId: keycloakClientId,
    exchange: 'refresh',
    oidcRefreshToken: refreshToken,
    oidcOrigin: keycloakUrl,
    organizationName: keycloakRealm
  }
  const authProvider = await AuthProviders.refreshAuthProvider(oidcCredentials);
  const client = new NanoTDFClient(authProvider, access);
  const cipherText = await client.encrypt(plainText);
  const clearText = await client.decrypt(cipherText);
```

### Examples

Review examples to see how to integrate. See [Examples](https://github.com/opentdf/documentation/tree/feature/integrate/examples)

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
