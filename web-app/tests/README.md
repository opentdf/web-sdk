This folder container playwright, e2e tests for web-app,
running against a local or remote backend in proxy mode.


## Bring up backend behind local (vite dev server) proxy

To configure backend, you can either use the opentdf quickstart
or the backend repository directly.

### Quickstart

First, connect to your cluster or spin up a local cluster (e.g. using kind or minikube).

Next, check out the opentdf repository and start the quickstart.
```
git clone https://github.com/opentdf/opentdf.git
cd opentdf/quickstart
export OPENTDF_INGRESS_HOST_PORT=5432
export OPENTDF_LOAD_FRONTEND=
tilt up
```

Finally, bring up the web app:

```
cd web-app
npm run dev
```

## Run Tests

```
cd web-app/tests
npm i
npm test
```
