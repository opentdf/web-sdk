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

## Use the platform

### Generate Typescript code from platform protobufs
```
scripts/platform.sh
```
This will clone the platform repo and generate Typescript code in `lib/src/platform`.

### Import Typescript code

```

import { GetAttributeRequest } from './lib/src/platform/policy/attributes/attributes_pb';
import { Attribute, AttributeRuleTypeEnum } from './lib/src/platform/policy/objects_pb';

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
```

This is an example to import a `GetAttributeRequest` to request attribute information.

