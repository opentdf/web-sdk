# OpenTDF command line tool (for node)

## Usage

```
opentdf.mjs <auth options> <policy options> [encrypt|decrypt] [input file]
```

For example, to use the quickstart test, we should do something like:

```
echo hello-world >sample.txt
bin/opentdf.mjs encrypt \
  --kasEndpoint http://localhost:65432/api/kas \
  --oidcEndpoint http://localhost:65432 \
  --auth tdf:tdf-client:123-456 \
  --output sample.tdf \
  sample.txt
bin/opentdf.mjs \
  --kasEndpoint http://localhost:65432/api/kas \
  --oidcEndpoint http://localhost:65432 \
  --auth tdf:tdf-client:123-456 \
  decrypt sample.tdf
```

This is a placeholder for working through build and CI issues.

### References

- [yargs](http://yargs.js.org)
- [typescript CLI starter](https://github.com/khalidx/typescript-cli-starter)

