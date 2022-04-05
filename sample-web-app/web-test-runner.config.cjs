process.env.NODE_ENV = 'test';

module.exports = {
  nodeResolve: true,
  plugins: [require('@snowpack/web-test-runner-plugin')()],
  // Workaround for issue in latest react user-testing library that doesn't
  // check to see if we are in browser or jsdom first.
  testRunnerHtml: testFramework =>
    `<html>
      <body>
        <script>global = (typeof global === 'undefined') ? { document } : global</script>
        <script type="module" src="${testFramework}"></script>
      </body>
    </html>`,
};
