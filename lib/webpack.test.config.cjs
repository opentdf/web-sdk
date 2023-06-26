const { glob } = require('glob');
const path = require('path');
const webpack = require('webpack');

module.exports = {
  mode: 'development',
  // entry: getEntryPoints(),
  entry: './dist/web/tests/mocha/unit/attribute-set.spec.js',
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
    fallback: { "url": false },
  },
  optimization: {
    minimize: false, // Disable minification
  },
};

function getEntryPoints() {
  const entryPoints = glob.sync('./dist/web/tests/mocha/**/*.good.js');
  const entry = {};

  entryPoints.forEach((entryPoint) => {
    const name = entryPoint.replace('./tests/mocha/', '').replace('.ts', '');
    entry[name] = './' + entryPoint;
  });

  return entry;
}
