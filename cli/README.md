# OpenTDF command line tool (for node)

A sample application using node & ESM to import and test a project

## Usage

```sh
opentdf.mjs <auth options> <policy options> [encrypt|decrypt] [input file]
```

Sample round trip execution:

```sh
echo hello-world >sample.txt
bin/opentdf.mjs encrypt \
  --kasEndpoint http://localhost:65432/api/kas \
  --oidcEndpoint http://localhost:65432/auth/realms/opentdf \
  --auth tdf-client:123-456 \
  --containerType tdf3 \
  --output sample.tdf \
  sample.txt
bin/opentdf.mjs \
  --kasEndpoint http://localhost:65432/api/kas \
  --oidcEndpoint http://localhost:65432/auth/realms/opentdf \
  --auth tdf-client:123-456 \
  --containerType tdf3 \
  --userId alice@somewhere.there \
  decrypt sample.tdf
```

### Validate a TDF

`validate` checks that a file is a structurally valid TDF without decrypting it. It needs no
platform, KAS or OIDC options, and it reads only the end of the file, the central directory
and the manifest, so it works on files of any size.

```sh
bin/opentdf.mjs validate sample.tdf
```

It prints one JSON line to stdout, `{"valid":true}` or `{"valid":false,"reason":"..."}`. The
exit status is 0 when the file is valid, 3 when it is not, and any other nonzero value when the
check could not run, for example because the file is missing.

### References

- [yargs](http://yargs.js.org)
- [typescript CLI starter](https://github.com/khalidx/typescript-cli-starter)
