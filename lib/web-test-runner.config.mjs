import { esbuildPlugin } from '@web/dev-server-esbuild';
import { filePlugin } from '@web/test-runner-commands/plugins';

export default {
  coverage: true,
  coverageConfig: {
    report: true,
    reportDir: 'coverage/wtr',
    reporters: ['json'],
    threshold: {
      statements: 65,
      branches: 60,
      functions: 50,
    },
  },
  files: ['tests/**/*.test.ts', '!tests/mocha/**'],
  nodeResolve: {
    browser: true,
    exportConditions: ['browser'],
  },
  plugins: [esbuildPlugin({ ts: true }), filePlugin()],
};
