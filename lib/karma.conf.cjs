module.exports = function(config) {
  config.set({
    frameworks: ['mocha', 'chai', 'karma-typescript'],
    files: [
      // './tests/mocha/**/*.spec.js',
      './tests/mocha/testing.spec.js',
    ],
    browsers: ['Chrome'],
    reporters: ['progress', 'coverage', 'karma-typescript'],
    singleRun: true,
    karmaTypescriptConfig: {
      tsconfig: './tsconfig.json',
    },
    coverageReporter: {
      type: 'html',
      dir: 'coverage/'
    }
  });
};