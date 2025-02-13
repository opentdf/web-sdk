module.exports = function(config) {
  config.set({
    frameworks: ['mocha'],
    files: [
      './tests/mocha/dist/encrypt-decrypt.spec.js',
    ],
    reporters: ['progress'],
    plugins: [
      'karma-mocha',
      'karma-chrome-launcher',
    ],
    browsers: [
      'ChromeDebugging',
    ],
    customLaunchers: {
      ChromeDebugging: {
        base: 'Chrome',
        flags: [ '--remote-debugging-port=9333' ]
      }
    },
  });
};