import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        // Append the real client IP to X-Forwarded-For. Uvicorn trusts this proxy (127.0.0.1)
        // and uses the right-most untrusted entry, so a client-supplied value can't spoof it.
        xfwd: true,
      },
    },
  },
});
