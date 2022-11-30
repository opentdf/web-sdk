import { filePlugin } from '@web/test-runner-commands/plugins';

export default {
  coverage: true,
  coverageConfig: {
    reporters: ['html', 'text', 'text-summary'],
    threshold: {
      statements: 65,
      branches: 60,
      functions: 54,
    },
  },
  files: ['dist/esm/tests/web/**/*.test.js'],
  nodeResolve: {
    browser: true,
    exportConditions: ['browser'],
  },
  plugins: [filePlugin()],
};
