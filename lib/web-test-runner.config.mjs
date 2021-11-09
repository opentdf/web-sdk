import { filePlugin } from '@web/test-runner-commands/plugins';

export default {
  coverageConfig: {
    reporters: [
      'html',
      'text',
      'text-summary',
    ],
    threshold: {
      statements: 70,
      branches: 70,
      functions: 70,
      lines: 70,
    },
  },
  files: ['dist/esm/test/**/*.test.js'],
  nodeResolve: {
    browser: true,
    exportConditions: ['browser'],
  },
  plugins: [filePlugin()],
};
