#!/usr/bin/env node

// Simplest HTTP server that supports RANGE headers AFAIK.
import { serve } from './static-server.js';

const dirname = new URL('.', import.meta.url).pathname;
const port = 8000;
const file = process.argv.length == 3 ? process.argv[2] : 'README.md';
const path = file.startsWith('/') ? file : `${dirname}${file}`;

await serve(path, port);
