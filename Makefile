
version=2.1.0
extras=cli remote-store web-app
pkgs=lib $(extras)

.PHONY: all audit ci clean cli format i license-check lint start test

start: all
	(cd web-app && npm run dev)

cli: cli/opentdf-cli-$(version).tgz

clean:
	rm -f *.tgz
	rm -f */*.tgz
	rm -rf */dist
	rm -rf */node_modules

ci: lib/opentdf-client-$(version).tgz
	for x in $(extras); do (cd $$x && npm uninstall @opentdf/client && npm ci && npm i ../lib/opentdf-client-$(version).tgz) || exit 1; done

i:
	(cd lib && npm i && npm pack)
	for x in $(extras); do (cd $$x && npm uninstall @opentdf/client && npm i && npm i ../lib/opentdf-client-$(version).tgz) || exit 1; done

all: ci lib/opentdf-client-$(version).tgz remote-store/opentdf-remote-store-$(version).tgz web-app/opentdf-web-app-$(version).tgz

cli/opentdf-cli-$(version).tgz: lib/opentdf-client-$(version).tgz $(shell find cli -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd cli && npm uninstall @opentdf/client && npm ci && npm i ../lib/opentdf-client-$(version).tgz && npm pack)

remote-store/opentdf-remote-store-$(version).tgz: lib/opentdf-client-$(version).tgz $(shell find remote-store -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd remote-store && npm uninstall @opentdf/client && npm ci && npm i ../lib/opentdf-client-$(version).tgz && npm pack)

web-app/opentdf-web-app-$(version).tgz: lib/opentdf-client-$(version).tgz $(shell find web-app -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd web-app && npm uninstall @opentdf/client && npm ci && npm i ../lib/opentdf-client-$(version).tgz && npm pack && npm run build)

lib/opentdf-client-$(version).tgz: $(shell find lib -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd lib && npm ci --including=dev && npm pack)

dist: lib/opentdf-client-$(version).tgz
	(cp lib/opentdf-client-$(version).tgz ./)

audit:
	for x in $(pkgs); do (cd $$x && npm audit --omit dev) || exit 1; done

format license-check lint test: ci
	for x in $(pkgs); do (cd $$x && npm run $@) || exit 1; done

doc:
	cd lib && npm run doc
