#! /bin/bash
cd lib
npm ci
npm run build
npm pack
cd ..

# update cli to use new build
cd cli
npm remove @opentdf/sdk  
npm add file:../lib/opentdf-sdk-0.4.0.tgz

# update web-app to use new build
cd .. 
cd web-app
npm remove @opentdf/sdk  
npm add file:../lib/opentdf-sdk-0.4.0.tgz