import path from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8080',
    },
  },
  build: {
    // Ships straight into the Go binary via go:embed — see
    // backend/web/embed.go. emptyOutDir keeps the placeholder file out of
    // the final embedded build.
    outDir: '../backend/web/dist',
    emptyOutDir: true,
  },
})
