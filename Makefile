
version=0.0.1
pkgs=lib cli sample-web-app

.PHONY: all license-check lint test ci i start format clean

start: all
	(cd sample-web-app && npm run start)

clean:
	rm *.tgz

ci: opentdf-client-$(version).tgz
	for x in cli sample-web-app; do (cd $$x && npm uninstall @opentdf/client && npm ci && npm i ../opentdf-client-$(version).tgz) || exit 1; done

i:
	(cd lib && npm i && npm pack --pack-destination ../)
	for x in cli sample-web-app; do (cd $$x && npm uninstall @opentdf/client && npm i && npm i ../opentdf-client-$(version).tgz) || exit 1; done

all: ci opentdf-client-$(version).tgz opentdf-cli-$(version).tgz opentdf-sample-web-app-$(version).tgz

opentdf-cli-$(version).tgz: opentdf-client-$(version).tgz $(shell find cli -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd cli && npm ci ../opentdf-client-$(version).tgz && npm pack --pack-destination ../)

opentdf-sample-web-app-$(version).tgz: opentdf-client-$(version).tgz $(shell find sample-web-app -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd sample-web-app && npm ci ../opentdf-client-$(version).tgz && npm pack --pack-destination ../)

opentdf-client-$(version).tgz: $(shell find lib -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd lib && npm ci --including=dev && npm pack --pack-destination ../)

format license-check lint test: ci
	for x in $(pkgs); do (cd $$x && npm run $@) || exit 1; done
	
