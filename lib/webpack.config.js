const path = require('path');

const prodPattern = /^prod/i;

module.exports = (env, argv) => {
  const isProd = prodPattern.test(argv.mode) || prodPattern.test(process.env.NODE_ENV);
  const mode = isProd ? 'production' : 'development';

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
      },
    },
    output: {
      publicPath: '',
      iife: true,
      library: {
        name: '@opentdf/client',
        type: 'module',
      },
      filename: `client-web.web.js`,
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
      publicPath: '',
      libraryExport: 'default',
      globalObject: 'this',
      libraryTarget: 'commonjs',
      filename: `node.cjs.js`,
      path: path.resolve(__dirname, 'dist/server'),
    },
  };

  return [clientConfig, serverConfig];
};
