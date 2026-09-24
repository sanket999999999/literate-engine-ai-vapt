import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    // Built straight into the backend, so `python run.py` serves the whole app
    // on one port with no separate web server.
    outDir: '../vapt/web/dist',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    // In dev the Vite server owns the page and forwards API calls to FastAPI.
    proxy: {
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true },
    },
  },
});
