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

### Decrypting part of a file

`decrypt` takes a plaintext byte range with `--offset` and `--length`, with the same meaning as
`Blob.slice`. Only the segments needed for the range are read and decrypted. Omitting `--length`
reads to the end, and a range running past the end stops there. An offset equal to the plaintext
size prints nothing; an offset past it is an error (exit status 1). The input may be a local path or
an `http(s)` URL, which is read with HTTP Range requests.

```sh
bin/opentdf.mjs <auth options> --offset 1048576 --length 4096 \
  decrypt https://example.com/sample.tdf
```

### References

- [yargs](http://yargs.js.org)
- [typescript CLI starter](https://github.com/khalidx/typescript-cli-starter)
