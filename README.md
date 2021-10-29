# opentdf for the web

This project is focused on providing web client support for the opentdf family of data protection formats and protocols. Notably, it will a web-friendly library `@opentdf/client`, and tools and support for testing it and building it into web applications.

## Contributing to this repository

[![Integration Test](https://github.com/opentdf/client-web/actions/workflows/ci.yaml/badge.svg)](https://github.com/opentdf/client-web/actions/workflows/ci.yaml)

Developing with this code requires a recent version of `npm` and `node`. We recommend installing `nvm` and useing this to manage your node installation. To checkout, vuild, validate your installation, and test the sample web appliation, you may:

```sh
git checkout https://github.com/opentdf/webclient
cd webclient
nvm use
make test
make start
```
