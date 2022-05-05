// Karma configuration
// Generated on Mon Jan 11 2021 15:36:54 GMT-0600 (Central Standard Time)
const NodePolyfillPlugin = require('node-polyfill-webpack-plugin');
const path = require('path');

module.exports = (config) => {
  config.set({
    client: {
      mocha: {
        timeout: 10000, // 10 seconds - upped from 2 seconds
      },
    },
    frameworks: ['mocha', 'chai', 'karma-typescript'],

    plugins: [
      'karma-webpack',
      'karma-chai',
      'karma-mocha',
      'karma-chrome-launcher',
      'karma-coverage',
      'karma-typescript',
    ],
    preprocessors: {
      'src/**/*': ['webpack', 'coverage'],
      'test/**/*': ['webpack'],
    },
    // list of files / patterns to load in the browser
    files: [
      { pattern: 'src/**/*.+(js|ts)' },
      { pattern: 'test/**/*.karma.+(js|ts)' },
      { pattern: 'test/unit/tdf.spec.+(js|ts)' },
      { pattern: 'test/unit/crypto/*' },
    ],

    // list of files / patterns to exclude
    exclude: [],

    // test results reporter to use
    // possible values: 'dots', 'progress'
    // available reporters: https://npmjs.org/browse/keyword/karma-reporter
    reporters: ['progress', 'coverage'],

    coverageReporter: {
      // specify a common output directory
      dir: 'build/reports/coverage',
      reporters: [
        { type: 'html', subdir: 'report-html' },
        { type: 'lcov', subdir: 'report-lcov' },
      ],
    },

    // web server port
    port: 9876,

    // enable / disable colors in the output (reporters and logs)
    colors: true,

    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_INFO,

    // enable / disable watching file and executing tests whenever any file changes
    autoWatch: true,

    // start these browsers
    // available browser launchers: https://npmjs.org/browse/keyword/karma-launcher
    browsers: ['ChromeHeadlessNoSandbox'],
    customLaunchers: {
      ChromeHeadlessNoSandbox: {
        base: 'ChromeHeadless',
        flags: ['--no-sandbox'],
      },
    },
    // Continuous Integration mode
    // if true, Karma captures browsers, runs the tests and exits
    singleRun: false,

    // Concurrency level
    // how many browser should be started simultaneous
    concurrency: Infinity,
    webpack: {
      resolve: {
        extensions: ['.js', '.ts'],
        fallback: {
          //   constants: require.resolve('constants-browserify'),
          //   crypto: require.resolve('crypto-browserify'),
          fs: false,
          //   path: require.resolve('path-browserify'),
          //   stream: require.resolve('stream-browserify'),
        },
      },
      plugins: [new NodePolyfillPlugin()],
      module: {
        rules: [
          {
            test: /\.ts?$/,
            use: 'ts-loader',
            exclude: /node_modules/,
          },
          {
            test: /\.js?$/,
            exclude: /node_modules/,
            resolve: {
              fullySpecified: false, // disable the behaviour
              alias: {
                crypto: path.resolve(__dirname, 'node_modules/crypto-js'),
              },
            },
            use: {
              loader: 'babel-loader',
              options: {
                presets: [
                  [
                    '@babel/preset-env',
                    {
                      targets: {
                        ie: '11',
                      },
                    },
                  ],
                ],
                plugins: [
                  ['@babel/plugin-syntax-dynamic-import'],
                  ['@babel/plugin-transform-runtime'],
                ],
              },
            },
          },
        ],
      },
    },
  });
};
