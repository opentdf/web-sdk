
version=0.0.1
pkgs=lib cli sample-web-app

.PHONY: all lint test ci i start format clean

clean:
	rm *.tgz

start: all
	(cd sample-web-app && npm run start)

ci:
	(cd lib && npm ci && npm pack --pack-destination ../)
	for x in cli sample-web-app; do (cd $$x && npm ci || exit 1); done

i:
	for x in $(pkgs); do (cd $$x && npm i --include=dev || exit 1); done

all: ci opentdf-client-$(version).tgz opentdf-cli-$(version).tgz opentdf-sample-web-app-$(version).tgz

opentdf-cli-$(version).tgz: opentdf-client-$(version).tgz $(shell find cli -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd cli && npm i ../opentdf-client-$(version).tgz && npm pack --pack-destination ../)

opentdf-sample-web-app-$(version).tgz: opentdf-client-$(version).tgz $(shell find sample-web-app -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd sample-web-app && npm i ../opentdf-client-$(version).tgz && npm pack --pack-destination ../)

opentdf-client-$(version).tgz: $(shell find lib -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	(cd lib && npm ci --including=dev && npm pack --pack-destination ../)

test: ci
	for x in $(pkgs); do (cd $$x && npm test) || exit 1; done

lint: ci
	for x in $(pkgs); do (cd $$x && npm run lint) || exit 1; done

format: ci
	for x in $(pkgs); do (cd $$x && npm run format); done
	
