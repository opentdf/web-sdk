import { createRequire } from 'node:module'
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const require = createRequire(import.meta.url)

// https://vitejs.dev/config/
export default defineConfig({
  build: {
    rollupOptions: {
      shimMissingExports: true
    }
  },
  plugins: [react()],
  server: {
    port: 65432,
    proxy: {
      '/kas': 'http://localhost:8080',
      '/auth': 'http://localhost:8888',
    },
  },
});
