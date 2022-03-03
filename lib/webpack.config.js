import path from 'path';
import NodePolyfillPlugin from 'node-polyfill-webpack-plugin';
const __dirname = path.resolve();

export default {
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
    extensions: ['.tsx', '.ts', '.js'],
    modules: ['src', 'node_modules'],
    fallback: {
      crypto: false,
    }
  },
  output: {
    publicPath: '',
    globalObject: 'this',
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist'),
  },
};
