# OpenTDF command line tool (for node)

A sample application using node & ESM to import and test a project

## Usage

```sh
opentdf.mjs <auth options> <policy options> [encrypt|decrypt] [input file]
```

For example, to use the quickstart test, we should do something like:

```sh
echo hello-world >sample.txt
bin/opentdf.mjs encrypt \
  --kasEndpoint http://localhost:65432/api/kas \
  --oidcEndpoint http://localhost:65432/auth/realms/tdf \
  --auth tdf-client:123-456 \
  --containerType tdf3 \
  --output sample.tdf \
  sample.txt
bin/opentdf.mjs \
  --kasEndpoint http://localhost:65432/api/kas \
  --oidcEndpoint http://localhost:65432/auth/realms/tdf \
  --auth tdf-client:123-456 \
  --containerType tdf3 \
  --userId alice@somewhere.there \
  decrypt sample.tdf
```

This is a placeholder for working through build and CI issues.

### References

- [yargs](http://yargs.js.org)
- [typescript CLI starter](https://github.com/khalidx/typescript-cli-starter)
