import { createRequire } from 'node:module'
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const require = createRequire(import.meta.url)

function proxy(): Record<string, string> {
  console.log(process.env);
  const { VITE_PROXY } = process.env;
  if (VITE_PROXY) {
    console.log(`using VITE_PROXY [${VITE_PROXY}]`);
    return JSON.parse(VITE_PROXY);
  }
  console.log("using standard VITE_PROXY");
  return {
    '/kas': 'http://localhost:8080',
    '/auth': 'http://localhost:8888',
  };
}

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
    proxy: proxy(),
  },
});
