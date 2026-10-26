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

The input to `decrypt` may be a local path or an `http(s)` URL, which is read with HTTP Range
requests.

### Decrypting part of a file

`decrypt` can decrypt selected portions of ciphertext. `--offset` and `--length` are byte positions
in the decrypted data, and only the segments that hold those bytes are read and decrypted. As with
`Blob.slice(offset, offset + length)`, omitting `--length` reads to the end, a range running past
the end stops there, and an offset equal to the size of the decrypted data prints nothing. Unlike
`Blob.slice`, an offset past the end is an error (exit status 1), as are negative or non-decimal
values.

```sh
bin/opentdf.mjs <auth options> --offset 1048576 --length 4096 \
  decrypt https://example.com/sample.tdf
```

### References

- [yargs](http://yargs.js.org)
- [typescript CLI starter](https://github.com/khalidx/typescript-cli-starter)
