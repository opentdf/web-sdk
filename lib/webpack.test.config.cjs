const { glob } = require('glob');
const path = require('path');
const webpack = require('webpack');

module.exports = {
  mode: 'development',
  entry: getEntryPoints(),
  output: {
    path: path.resolve(__dirname, 'tests/mocha/dist'),
    filename: '[name].spec.js',
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
    const name = entryPoint.replace('./tests/mocha/', '').replace('.ts', '');
    entry[name] = './' + entryPoint;
  });

  return entry;
}
