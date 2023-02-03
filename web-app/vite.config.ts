import { createRequire } from 'node:module'
import { defineConfig } from 'vite';
import inject from '@rollup/plugin-inject';
import react from '@vitejs/plugin-react';

const require = createRequire(import.meta.url)

// https://vitejs.dev/config/
export default defineConfig({
  build: {
    rollupOptions: {
      shimMissingExports: true,
      plugins: [
        inject({
          Buffer: [require.resolve('buffer'), 'Buffer']
        })
      ]
    }
  },
  plugins: [react()],
  server: {
    port: 65432,
    proxy: {
      '/api': 'http://localhost:5432',
      '/auth': 'http://localhost:5432',
    },
  },
});
