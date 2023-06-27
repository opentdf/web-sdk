import http from 'http';

function range(start, end) {
  const result = [];
  for (let i = start; i <= end; i++) {
    result.push(i);
  }
  return new Uint8Array(result);
}

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Range');
  if (req.url === '/file' && req.method === 'GET') {
    const start = 0;
    const end = 255;
    const fullRange = range(start, end);

    const rangeHeader = req.headers.range;
    if (rangeHeader) {
      const bytesRange = rangeHeader.replace('bytes=', '').split('-');
      let rangeData;
      let rangeStart;
      let rangeEnd;
      if (!bytesRange[0]) {
        rangeStart = parseInt(rangeHeader.replace('bytes=', ''));
        rangeData = fullRange.slice(rangeStart)
      } else {
        rangeStart = parseInt(bytesRange[0], 10);
        rangeEnd = parseInt(bytesRange[1], 10) || end;
        rangeData = fullRange.slice(rangeStart, rangeEnd + 1);

        if (rangeStart > rangeEnd) {
          res.statusCode = 416; // Range Not Satisfiable
          res.setHeader('Content-Range', `*/${end + 1}`);
          res.end();
          return;
        }
      }

      res.statusCode = 206; // Partial Content
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Length', rangeData.length);
      res.end(Buffer.from(rangeData.buffer));
    } else {
      res.statusCode = 200; // OK
      res.setHeader('Content-Type', 'application/octet-stream');
      res.end(Buffer.from(fullRange.buffer));
    }
  } else if (req.method === 'OPTIONS') {
    res.statusCode = 200;
    res.end();
  } else {
    res.statusCode = 404; // Not Found
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