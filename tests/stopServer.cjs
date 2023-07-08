const http = require('http');

(() => {
  const options = {
    host: 'localhost',
    port: 3000,
    path: '/stop',
    method: 'GET',
  };

  const req = http.request(options, (res) => {
    console.log(`Server stopped with response status: ${res.statusCode}`);
  });

  req.on('error', (e) => {
    console.error(`Error stopping server: ${e.message}`);
  });

  req.end();
})()