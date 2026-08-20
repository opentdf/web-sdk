import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}'],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    coverage: {
      provider: 'v8',
      // lcov for SonarCloud, text so a local run says something without
      // opening a file. sonar.sources already lists web-app/src, so without a
      // report every file here counts as uncovered new code.
      reporter: ['text', 'lcov'],
      // Report on all of src, not just the files a test happened to import.
      // Sonar treats absent files as uncovered anyway; listing them keeps the
      // local summary honest about how little of the demo app is tested.
      //
      // App.tsx will sit at 0% here no matter what: App.test.tsx drives it
      // through a real browser against `vite preview`, so it executes in a
      // process this provider never instruments.
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.d.ts', 'src/**/*.{test,spec}.{ts,tsx}'],
    },
  },
});
