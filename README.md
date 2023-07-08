# An OpenTDF Javascript Library for Browsers

This project packages a set of javascript modules that can write and read
a variety of OpenTDF data formats, including NanoTDF, Dataset TDF, and the
TDF3 with JSON envelopes.



## Usage

### Github Packages npm registry

https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-npm-registry#authenticating-with-a-personal-access-token

```shell
npm login --auth-type=legacy --registry=https://npm.pkg.github.com --scope=@arkavo-org
```

### Example

```typescript
const authProvider: AuthProvider = new OIDCExternalJwtProvider({clientId: "", externalJwt: "", oidcOrigin: ""})
const client = new NanoTDFClient(this.authProvider, "https://arkavo.net");
const plainText = "hello world"
const cipherText = await client.encrypt(plainText);
const clearText = await client.decrypt(cipherText);
```
