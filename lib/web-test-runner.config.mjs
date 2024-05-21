import { esbuildPlugin } from '@web/dev-server-esbuild';
import { filePlugin } from '@web/test-runner-commands/plugins';

export default {
  files: ['tests/web/nano-roundtrip.test.ts'],
  nodeResolve: {
    browser: true,
    exportConditions: ['browser'],
  },
  plugins: [esbuildPlugin({ ts: true }), filePlugin()],
};
