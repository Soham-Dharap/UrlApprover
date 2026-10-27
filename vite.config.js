import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  // The app is also served through preview proxies, whose hostname varies.
  server: { allowedHosts: true },
});
