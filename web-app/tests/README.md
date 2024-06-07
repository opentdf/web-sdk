# Web App Test Harness

This folder container playwright, e2e tests for web-app,
running against a local or remote backend in proxy mode.

## Bring up the platform behind local (vite dev server) proxy

Bring up test backend services (identity provider, database, etc.):

```sh
cd .github/workflows/roundtrip/
docker compose up -d
```

> You can leave off the `-d` to track the logs; 
> if you do this, open a new terminal
> and continue with the instructions below.

Configure the identity provider with some test users.
Please remain in the `roundtrip` test directory.

```sh
go run github.com/opentdf/platform/service@latest provision keycloak
./config-demo-idp.sh
```

If you haven't already done so, initialize your service keys.
Be careful!
If you lose these keys you will lose access to all TDFs encrypted with them.

```sh
./init-temp-keys.sh
```

Start the platform and its key access service:

```sh
go run github.com/opentdf/platform/service@latest start
```

## Run Tests

Once the platform is running, you may:

```sh
cd web-app/tests
npm i
npm test
```

To enable the large file tests, set

```sh
PLAYWRIGHT_TESTS_TO_RUN=huge roundtrip
```


## Running with test server for local URL streaming tests

To try encrypting some of your own files via HTTP:

```sh
cd web-app/tests
npm i
./run-server.js ~/Downloads
```

Then use the OR URL field in the sample app to load things up.
