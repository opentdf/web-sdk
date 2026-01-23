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
  --kasEndpoint http://localhost:8080/kas \
  --oidcEndpoint http://localhost:8888/auth/realms/opentdf \
  --auth opentdf:secret \
  --containerType tdf3 \
  --output sample.tdf \
  sample.txt
bin/opentdf.mjs \
  --kasEndpoint http://localhost:8080/kas \
  --oidcEndpoint http://localhost:8888/auth/realms/opentdf \
  --auth opentdf:secret \
  --containerType tdf3 \
  --ignoreAllowList \
  decrypt sample.tdf
```

### References

- [yargs](http://yargs.js.org)
- [typescript CLI starter](https://github.com/khalidx/typescript-cli-starter)
