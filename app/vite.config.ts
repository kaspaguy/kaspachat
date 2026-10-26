import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { readFileSync } from 'node:fs';

const version = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version;

// The app imports the protocol reference implementation straight from ../protocol/src, so the browser runs the
// exact code the test vectors check. Its crypto libraries resolve to this app's copies (same pinned versions).
export default defineConfig({
  plugins: [react()],
  define: { __APP_VERSION__: JSON.stringify(version) },
  resolve: { dedupe: ['@noble/ciphers', '@noble/curves', '@noble/hashes', '@noble/post-quantum', '@scure/bip39'] },
  server: { fs: { allow: ['..'] }, proxy: { '/api/relay': { target: 'http://127.0.0.1:5511', rewrite: (p) => p.replace(/^\/api\/relay/, '') }, '/api/index': { target: 'http://127.0.0.1:5510', rewrite: (p) => p.replace(/^\/api\/index/, '') } } },
  build: { target: 'es2022', sourcemap: false, chunkSizeWarningLimit: 1500 },
  worker: { format: 'es' },
});
