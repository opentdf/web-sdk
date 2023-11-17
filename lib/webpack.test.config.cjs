const { glob } = require('glob');
const path = require('node:path');
const webpack = require('webpack');

module.exports = {
  mode: 'development',
  entry: getEntryPoints(),
  output: {
    path: path.resolve(__dirname, 'tests/mocha/dist'),
    filename: '[name].js',
  },
  plugins: [
    new webpack.ProvidePlugin({
      Buffer: ['buffer', 'Buffer'],
    }),
  ],
  resolve: {
    extensions: ['.js'],
  },
  optimization: {
    minimize: false, // Disable minification
  },
};

function getEntryPoints() {
  const entryPoints = glob.sync('./dist/web/tests/mocha/**/*.spec.js');
  const entry = {};

  entryPoints.forEach((entryPoint) => {
    const name = entryPoint.replace('dist/web/tests/mocha/', '').replace('.js', '');
    entry[name] = './' + entryPoint;
  });

  return entry;
}
