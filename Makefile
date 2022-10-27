
version=0.3.1
pkgs=lib cli cli-commonjs web-app

.PHONY: all audit license-check lint test ci i start format clean

start: all
	(cd web-app && npm run start)

clean:
	rm -f *.tgz
	rm -f */*.tgz
	rm -rf */dist
	rm -rf */node_modules

ci: lib/opentdf-client-$(version).tgz
	for x in cli web-app; do (cd $$x && npm uninstall @opentdf/client && npm ci && npm i ../lib/opentdf-client-$(version).tgz) || exit 1; done

i:
	(cd lib && npm i && npm pack)
	for x in cli cli-commonjs web-app; do (cd $$x && npm uninstall @opentdf/client && npm i && npm i ../lib/opentdf-client-$(version).tgz) || exit 1; done

all: ci lib/opentdf-client-$(version).tgz cli/opentdf-cli-$(version).tgz cli-commonjs/opentdf-cli-commonjs-$(version).tgz web-app/opentdf-web-app-$(version).tgz

cli/opentdf-cli-$(version).tgz: lib/opentdf-client-$(version).tgz $(shell find cli -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd cli && npm ci ../lib/opentdf-client-$(version).tgz && npm pack)

cli-commonjs/opentdf-cli-commonjs-$(version).tgz: lib/opentdf-client-$(version).tgz $(shell find cli-commonjs -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd cli-commonjs && npm ci ../lib/opentdf-client-$(version).tgz && npm pack)

web-app/opentdf-web-app-$(version).tgz: lib/opentdf-client-$(version).tgz $(shell find web-app -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd web-app && npm ci ../lib/opentdf-client-$(version).tgz && npm pack)

lib/opentdf-client-$(version).tgz: $(shell find lib -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd lib && npm ci --including=dev && npm pack)

dist: lib/opentdf-client-$(version).tgz
	(cp lib/opentdf-client-$(version).tgz ./)

audit:
	for x in $(pkgs); do (cd $$x && npm audit) || exit 1; done

format license-check lint test: ci
	for x in $(pkgs); do (cd $$x && npm run $@) || exit 1; done

doc:
	cd lib && npm run doc
