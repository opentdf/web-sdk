// Minimal dev server with Cross-Origin Isolation headers required for SharedArrayBuffer.
// Usage: node serve.mjs [port]

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const PORT = parseInt(process.argv[2] || '8080', 10);
const ROOT = fileURLToPath(new URL('.', import.meta.url));

const MIME = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.mjs': 'application/javascript',
  '.wasm': 'application/wasm',
  '.json': 'application/json',
  '.css': 'text/css',
};

const server = createServer(async (req, res) => {
  const path = join(ROOT, req.url === '/' ? '/test.html' : req.url);
  try {
    const data = await readFile(path);
    const ext = extname(path);
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end('Not found');
  }
});

server.listen(PORT, () => {
  console.log(`Serving ${ROOT} on http://localhost:${PORT} (cross-origin isolated)`);
});
