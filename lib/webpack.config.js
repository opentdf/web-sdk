const path = require('path');
const NodePolyfillPlugin = require('node-polyfill-webpack-plugin');
const nodeExternals = require('webpack-node-externals');

const prodPattern = /^prod/i;

module.exports = (env, argv) => {
  const isProd = prodPattern.test(argv.mode) || prodPattern.test(process.env.NODE_ENV);
  const mode = (isProd)
    ? 'production'
    : 'development';
  // CRA fails to run build with mode: 'production'

  const clientConfig = {
    mode: 'development',
    devtool: 'source-map',
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
    resolve: {
      extensions: [ '.ts', '.tsx', '.js'],
      modules: ['src', 'node_modules'],
      fallback: {
        crypto: false,
        fs: false,
      }
    },
    output: {
      publicPath: '',
      library: '@opentdf/client',
      filename: `client-nano.web.js`,
      libraryTarget: 'umd',
      globalObject: 'this',
      umdNamedDefine: true,
      path: path.resolve(__dirname, 'dist/client'),
    },
  };

  const serverConfig = {
    mode,
    devtool: 'source-map',
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
    },
    output: {
      libraryExport: 'default',
      libraryTarget: 'umd',
      filename: `node-nano.cjs.js`,
      path: path.resolve(__dirname, 'dist/server'),
    },
  };

  const clientTdf3Config = {
    ...clientConfig,
    entry: './tdf3/index-web.js',
    plugins: [
      new NodePolyfillPlugin()
    ],
    output: {
      ...clientConfig.output,
      filename: `client-web.js`,
    },
  };

  const serverTdf3Config = {
    ...serverConfig,
    entry: './tdf3/index.js',
    externals: [nodeExternals()],
    resolve: {
      ...serverConfig.resolve,
      fallback: {
        fetch: require.resolve('node-fetch')
      },
      alias: {
        streamsaver: path.resolve(__dirname, '/tdf3/mocks/streamsaver'),
      },
    },
    output: {
      ...serverConfig.output,
      filename: `node.cjs.js`,
    },
  };

  return [
    clientConfig,
    serverConfig,
    clientTdf3Config,
    serverTdf3Config,
  ];
};
