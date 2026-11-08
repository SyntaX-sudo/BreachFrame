import { defineConfig } from '@playwright/test';

// The E2E suite drives the *real* desktop app (Rust backend + SQLite) through
// WebView2's DevTools protocol, so it runs on Windows. See e2e/desktop.spec.ts.
export default defineConfig({
  testDir: './e2e',
  timeout: 90_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
});
