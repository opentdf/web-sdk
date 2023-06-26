import http from 'http';
import fs from 'fs';
import path from 'path';

const __filename = new URL(import.meta.url).pathname;
const __dirname = path.dirname(__filename);

const server = http.createServer((req, res) => {
  if (req.url === '/README.md' && req.method === 'GET') {
    const filePath = path.join(__dirname, '../../README.md');

    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.statusCode = 500;
        res.end('Internal Server Error');
      } else {
        console.log('file returning')
        res.statusCode = 200;
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Access-Control-Allow-Origin', '*');  // Allow requests from any origin
        res.end(data);
      }
    });
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