// Simplest HTTP server that supports RANGE headers AFAIK.
import { createServer } from 'node:http';
import send from 'send';

const dirname = new URL('.', import.meta.url).pathname;
const port = 8000;
const file = process.argv.length == 3 ? process.argv[2] : 'README.md';
const path = file.startsWith('/') ? file : `${dirname}${file}`;

console.log(`Listening on port ${port}; serving up bits of ${path}`);
const server = createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Request-Method', '*');
  res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, GET');
  res.setHeader('Access-Control-Allow-Headers', req.headers.origin);
if (req.method === 'OPTIONS') {
  res.setHeader('Access-Control-Allow-Headers', 'Range');
 
    res.writeHead(200);
		res.end();
		return;
	}
  send(req, path).pipe(res);
});
server.listen(port);
