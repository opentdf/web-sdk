module.exports = function(config) {
  config.set({
    frameworks: ['mocha'],
    files: [
      './tests/mocha/dist/**/*.js',
    ],
    reporters: ['progress'],
    plugins: [
      'karma-mocha',
      'karma-chrome-launcher',
    ],
    browsers: ['ChromeHeadless'],
    singleRun: true,
  });
};