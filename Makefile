
version=0.2.0
extras=cli web-app
pkgs=lib $(extras)

.PHONY: all audit ci clean cli format i license-check lint start test

start: all
	(cd web-app && npm run dev)

cli: cli/opentdf-ctl-$(version).tgz

clean:
	rm -f *.tgz
	rm -f */*.tgz
	rm -rf */dist
	rm -rf */node_modules

ci: lib/opentdf-sdk-$(version).tgz
	for x in $(extras); do (cd $$x && npm uninstall @opentdf/sdk && npm ci && npm i ../lib/opentdf-sdk-$(version).tgz) || exit 1; done

i:
	(cd lib && npm i && npm pack)
	for x in $(extras); do (cd $$x && npm uninstall @opentdf/sdk && npm i && npm i ../lib/opentdf-sdk-$(version).tgz) || exit 1; done

all: ci lib/opentdf-sdk-$(version).tgz web-app/opentdf-web-app-$(version).tgz

cli/opentdf-ctl-$(version).tgz: lib/opentdf-sdk-$(version).tgz $(shell find cli -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd cli && npm uninstall @opentdf/sdk && npm ci && npm i ../lib/opentdf-sdk-$(version).tgz && npm pack)

web-app/opentdf-web-app-$(version).tgz: lib/opentdf-sdk-$(version).tgz $(shell find web-app -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd web-app && npm uninstall @opentdf/sdk && npm ci && npm i ../lib/opentdf-sdk-$(version).tgz && npm pack && npm run build)

lib/opentdf-sdk-$(version).tgz: $(shell find lib -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd lib && npm ci --including=dev && npm pack)

dist: lib/opentdf-sdk-$(version).tgz
	(cp lib/opentdf-sdk-$(version).tgz ./)

audit:
	for x in $(pkgs); do (cd $$x && npm audit --omit dev) || exit 1; done

format license-check lint: ci
	for x in $(pkgs); do (cd $$x && npm run $@) || exit 1; done

test: ci
	cd web-app && npx install playwright
	for x in $(pkgs); do (cd $$x && npm run $@) || exit 1; done

doc:
	cd lib && npm ci && npm run doc
