import http from 'http';
import fs from 'fs';
import path from 'path';

const __filename = new URL(import.meta.url).pathname;
const __dirname = path.dirname(__filename);
console.log(path.join(__dirname, './__fixtures__/testfile.bin'));

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');  // Allow requests from any origin
  if (req.url === '/file' && req.method === 'GET') {
    const filePath = path.join(__dirname, './__fixtures__/testfile.bin');

    console.log('file returning')
    const fileStream = fs.createReadStream(filePath);

    fileStream.on('data', (chunk) => {
      console.log('Received chunk:', chunk);
    });
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/octet-stream');
    fileStream.pipe(res);
  } else {
    res.statusCode = 404;
    res.end('Not Found');
  }
});

server.listen(3000, 'localhost', () => {
  console.log('Server running with disabled CORS at http://localhost:3000/');
});

const stopServer = () => {
  server.close(() => {
    console.log('Server gracefully terminated.');
  });
};


export { stopServer };