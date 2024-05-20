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
  --kasEndpoint http://localhost:8080/kas \
  --oidcEndpoint http://localhost:8888/auth/realms/opentdf \
  --auth tdf-client:123-456 \
  --containerType nano \
  --output sample.ntdf \
  sample.txt
bin/opentdf.mjs \
  --kasEndpoint http://localhost:8080 \
  --oidcEndpoint http://localhost:8888/auth/realms/opentdf \
  --containerType nano \
  --auth opentdf:secret \
  decrypt sample.ntdf
```

This is a placeholder for working through build and CI issues.

### References

- [yargs](http://yargs.js.org)
- [typescript CLI starter](https://github.com/khalidx/typescript-cli-starter)
