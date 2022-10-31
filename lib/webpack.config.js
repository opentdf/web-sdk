const path = require('path');
const nodeExternals = require('webpack-node-externals');
const webpack = require('webpack');

const prodPattern = /^prod/i;

module.exports = (env, argv) => {
  const isProd = prodPattern.test(argv.mode) || prodPattern.test(process.env.NODE_ENV);
  const mode = isProd ? 'production' : 'development';
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
      extensions: ['.ts', '.tsx', '.js'],
      modules: ['src', 'node_modules'],
      fallback: {
        crypto: false,
        fs: false,
        constants: false,
        stream: false,
      },
    },
    output: {
      publicPath: '',
      library: '@opentdf/client',
      filename: `nano.web.js`,
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
      extensions: ['.ts', '.tsx', '.js'],
      modules: ['src', 'node_modules'],
    },
    output: {
      libraryExport: 'default',
      libraryTarget: 'umd',
      filename: `nano.node.js`,
      path: path.resolve(__dirname, 'dist/server'),
    },
  };

  const clientTdf3Config = {
    ...clientConfig,
    entry: './tdf3/index-web.ts',
    plugins: [
      new webpack.ProvidePlugin({
        Buffer: ['buffer', 'Buffer'],
      }),
      new webpack.ProvidePlugin({
        process: 'process',
      }),
    ],
    resolve: {
      ...clientConfig.resolve,
      alias: {
        '@tdfStream': path.resolve(__dirname, '/tdf3/src/client/BrowserTdfSteam.ts'),
      },
      extensions: ['', '.js', '.jsx', '.ts', '.tsx'],
    },
    output: {
      ...clientConfig.output,
      filename: `tdf3.web.js`,
    },
  };

  const serverTdf3Config = {
    ...serverConfig,
    entry: './tdf3/index.ts',
    externals: [nodeExternals()],
    resolve: {
      ...serverConfig.resolve,
      alias: {
        '@tdfStream': path.resolve(__dirname, '/tdf3/src/client/NodeTdfStream.ts'),
      },
      extensions: ['', '.js', '.jsx', '.ts', '.tsx'],
    },
    output: {
      ...serverConfig.output,
      filename: `tdf3.node.js`,
    },
  };

  return [clientConfig, serverConfig, clientTdf3Config, serverTdf3Config];
};
