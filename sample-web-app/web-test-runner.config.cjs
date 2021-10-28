process.env.NODE_ENV = 'test';

module.exports = {
  nodeResolve: true,
  plugins: [require('@snowpack/web-test-runner-plugin')()],
};
