#!/usr/bin/env node

// Node strips the types itself, but only resolves the real file name.
import { serve } from './static-server.ts';

const dirname = new URL('.', import.meta.url).pathname;
const port = 8000;
const file = process.argv.length == 3 ? process.argv[2] : 'README.md';
const path = file.startsWith('/') ? file : `${dirname}${file}`;

await serve(path, port);
