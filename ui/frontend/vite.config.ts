import path from 'node:path'
import { readFileSync } from 'node:fs'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

interface PackageLock {
  packages: Record<string, { version?: string }>
}

const packageLock = JSON.parse(readFileSync(new URL('./package-lock.json', import.meta.url), 'utf8')) as PackageLock
const frontendOSSVersions = [
  ['React', 'react'],
  ['React Router', 'react-router-dom'],
  ['Radix UI Dialog', '@radix-ui/react-dialog'],
  ['Tailwind CSS', 'tailwindcss'],
  ['Vite', 'vite'],
].map(([name, packageName]) => ({
  name,
  version: packageLock.packages[`node_modules/${packageName}`]?.version ?? 'unknown',
}))

// https://vite.dev/config/
export default defineConfig({
  define: {
    __FRONTEND_OSS_VERSIONS__: JSON.stringify(frontendOSSVersions),
  },
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
