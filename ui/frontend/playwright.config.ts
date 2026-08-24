import { defineConfig, devices } from '@playwright/test'

// Runs against a real deployment (see .github/workflows/ui-e2e.yml — a kind
// cluster with the actual chart installed, port-forwarded to E2E_BASE_URL),
// not a dev server this config starts itself: there is no `webServer` entry
// here on purpose. `npm run e2e` locally expects the same thing — start
// your own target first (`npm run dev`, or a real deployment) and point
// E2E_BASE_URL at it.
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://127.0.0.1:8080',
    // The app picks its default language from navigator.language (see
    // LanguageContext.tsx) — pinned here so assertions on English copy
    // don't depend on whatever locale the runner happens to have.
    locale: 'en-US',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
