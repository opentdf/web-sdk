import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 65432,
    proxy: {
      '/api': 'http://localhost:5432',
      '/auth': 'http://localhost:5432',
    },
  },
});
