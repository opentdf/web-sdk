import path from 'path';
import webpack from 'webpack';
import NodePolyfillPlugin from 'node-polyfill-webpack-plugin';
import { createRequire } from "module";
const __dirname = path.resolve();
const require = createRequire(import.meta.url);

const prodPattern = /^prod/i;

const filename = 'client-web';

const output = {
  path: path.resolve(__dirname, 'dist')
};

export default (env, argv) => {
  const isProd = prodPattern.test(argv.mode) || prodPattern.test(process.env.NODE_ENV);
  const mode = (isProd)
    ? 'production'
    : 'development';

  const clientConfig = {
    mode,
    name: 'client',
    entry: './src/index-web.ts',
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
      extensions: ['.tsx', '.ts', '.js'],
      modules: ['src', 'node_modules'],
      fallback: {
        crypto: false,
      }
    },
    output: {
      publicPath: '',
      globalObject: 'this',
      filename: `${filename}.web${isProd ? '.min' : ''}.js`,
      path: path.resolve(__dirname, 'dist/client'),
    },
  };

  const serverConfig = {
    mode,
    name: 'server',
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
    target: 'node',
    resolve: {
      extensions: ['.tsx', '.ts', '.js'],
      modules: ['src', 'node_modules'],
      fallback: {
        fetch: require.resolve('node-fetch')
      }
    },
    output: {
      publicPath: '',
      globalObject: 'this',
      filename: `${filename}.cjs.js`,
      libraryTarget: 'commonjs2',
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
