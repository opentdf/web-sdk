const http = require('http');

function stopServer() {
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
}

module.exports = function(config) {
  config.set({
    frameworks: ['mocha', 'chai'],
    files: [
      './tests/mocha/dist/**/*.spec.js',
    ],
    browsers: ['Chrome'],
    reporters: ['progress', 'coverage'],
    singleRun: true,
    coverageReporter: {
      type: 'html',
      dir: 'coverage/'
    },
    port: 9877,
    onComplete: function () {
      stopServer();
    },
  });
};