const path = require('path');
const webpack = require('webpack');
const NodePolyfillPlugin = require('node-polyfill-webpack-plugin');

const prodPattern = /^prod/i;

module.exports = (env, argv) => {
  const isProd = prodPattern.test(argv.mode) || prodPattern.test(process.env.NODE_ENV);
  const mode = (isProd)
    ? 'production'
    : 'development';

  const clientConfig = {
    mode: 'development',
    name: 'client',
    entry: './src/index.ts',
    module: {
      rules: [
        {
          test: /\.tsx?$/,
          use: 'ts-loader',
          exclude: /node_modules/,
        },
      ],
    },
    target: 'web',
    plugins: [
      new NodePolyfillPlugin()
    ],
    resolve: {
      extensions: [ '.ts', '.tsx', '.js'],
      modules: ['src', 'node_modules'],
      fallback: {
        crypto: false,
      }
    },
    output: {
      publicPath: '',
      library: '@opentdf/client',
      filename: `client-web.web.js`,
      libraryTarget: 'umd',
      globalObject: 'this',
      umdNamedDefine: true,
      path: path.resolve(__dirname, 'dist/client'),
    },
  };

  const serverConfig = {
    mode,
    name: 'server',
    entry: './src/index.node.ts',
    module: {
      rules: [
        {
          test: /\.tsx?$/,
          use: 'ts-loader',
          exclude: /node_modules/,
        },
      ],
    },
    target: 'node',
    resolve: {
      extensions: [ '.ts', '.tsx', '.js'],
      modules: ['src', 'node_modules'],
      fallback: {
        fetch: require.resolve('node-fetch')
      }
    },
    output: {
      publicPath: '',
      globalObject: 'this',
      libraryTarget: 'umd',
      library: '@opentdf/client',
      filename: `node.cjs.js`,
      path: path.resolve(__dirname, 'dist/server'),
    },
    plugins: [
      new webpack.ProvidePlugin({
        fetch: ['node-fetch', 'default'],
      }),
    ],
  };

  return [
    clientConfig,
    serverConfig
  ];
};
