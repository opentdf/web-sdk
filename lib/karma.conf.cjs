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
    }
  });
};