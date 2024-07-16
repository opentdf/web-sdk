# OpenTDF Web Browser Client opentdf

This project is focused on providing web client support for the OpenTDF platform.
This includes encrypting and decrypting TDF content,
and some management tasks for ABAC.

## Usage

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

## Build and Test

```shell
make
```

## Contribute

### Prerequisites

Developing with this code requires a recent version of `npm` and `node`.
We develop using [nvm](https://github.com/nvm-sh/nvm#readme),
which allows us to pin to the same version of `npm` easily.

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

## Use the platform

Version 2 of this library adds support for ABAC management tasks.
This is provided with the [opentdf Platform](https://github.com/opentdf/platform).

### Generate Typescript code from platform protobufs

```sh
scripts/platform.sh
```

This will clone the platform repo and generate Typescript code in `lib/src/platform`.

### Import Typescript code

```ts
import { GetAttributeRequest } from './lib/src/platform/policy/attributes/attributes_pb';
import { Attribute, AttributeRuleTypeEnum } from './lib/src/platform/policy/objects_pb';
import {
    createConnectTransport,
} from '@connectrpc/connect-web'
import {
    createPromiseClient,
} from '@connectrpc/connect'

const attrData = {
    name: "my-attr",
    rule: AttributeRuleTypeEnum.ALL_OF,
    namespace: {name: 'my-namespace'},
    values: [{value: 'my-value'}],
    active: true,
    extraField: 'this will be ignored' // only proto defined fields and value types are respected
}
const attr = new Attribute(attrData);
console.log(attr.toJson());

// {
//     namespace: { name: 'my-namespace' },
//     name: 'my-attr',
//     rule: 'ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF',
//     values: [ { value: 'my-value' } ],
//     active: true
// }

const req = new GetAttributeRequest({id: 'uuid-here'});
const client = createPromiseClient(
    AttributesService,
    createConnectTransport({
        baseUrl: 'localhost:8080',
    })
)
```

This is an example to instantiate an `Attribute` and create a `GetAttributeRequest`.
