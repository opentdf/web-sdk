import { filePlugin } from '@web/test-runner-commands/plugins';

export default {
  coverage: true,
  coverageConfig: {
    reporters: ['html', 'text', 'text-summary'],
    threshold: {
      statements: 65,
      branches: 60,
      functions: 56,
    },
  },
  files: ['dist/esm/test/**/*.test.js'],
  nodeResolve: {
    browser: true,
    exportConditions: ['browser'],
  },
  plugins: [filePlugin()],
};
