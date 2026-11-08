/**
 * End-to-end tests against the real BreachFrame desktop binary.
 *
 * The app is started with an isolated, temporary data directory
 * (BREACHFRAME_DATA_DIR) and WebView2 remote debugging enabled, then driven
 * with Playwright over CDP. Nothing is mocked: every click goes through the
 * Tauri IPC layer into the Rust engine and SQLite.
 *
 * Requirements: Windows (WebView2) and a built binary:
 *   npm run build && cargo build -p breachframe-app
 * Set BREACHFRAME_BIN to use a different binary, and SCREENSHOTS=1 to refresh
 * docs/screenshots.
 */
import { test, expect, chromium, type Browser, type Page } from '@playwright/test';
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const PORT = 9333;
const ROOT = path.resolve(import.meta.dirname, '..');
const BIN = process.env.BREACHFRAME_BIN ?? path.join(ROOT, 'target', 'debug', process.platform === 'win32' ? 'breachframe-app.exe' : 'breachframe-app');
const SHOTS = process.env.SCREENSHOTS === '1';
const SHOT_DIR = path.join(ROOT, 'docs', 'screenshots');

test.skip(process.platform !== 'win32', 'CDP automation of the desktop webview requires WebView2 (Windows)');
test.skip(!existsSync(BIN), `desktop binary not found at ${BIN}; run "npm run build && cargo build -p breachframe-app"`);

let app: ChildProcess;
let browser: Browser;
let page: Page;
let dataDir: string;

async function waitForCdp(): Promise<void> {
  const deadline = Date.now() + 45_000;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`http://127.0.0.1:${PORT}/json/version`);
      if (r.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error('WebView2 DevTools endpoint did not come up');
}

async function shot(name: string) {
  if (!SHOTS) return;
  mkdirSync(SHOT_DIR, { recursive: true });
  // Keep transient toasts and machine-specific banners out of the docs.
  for (const b of await page.getByRole('button', { name: 'Dismiss' }).all()) await b.click({ timeout: 1000 }).catch(() => undefined);
  const banner = page.getByRole('button', { name: 'Dismiss discovered configurations' });
  if (await banner.isVisible()) await banner.click({ timeout: 2000 }).catch(() => undefined);
  await page.waitForTimeout(600);
  await page.screenshot({ path: path.join(SHOT_DIR, `${name}.png`) });
}

// Numbered frames for docs/demo.gif (assembled with ffmpeg, see docs/building.md).
const FRAME_DIR = path.join(ROOT, 'test-results', 'demo-frames');
let frameNo = 0;
async function frame(holdMs = 250) {
  if (!SHOTS) return;
  mkdirSync(FRAME_DIR, { recursive: true });
  await page.waitForTimeout(holdMs);
  await page.screenshot({ path: path.join(FRAME_DIR, `${String(++frameNo).padStart(3, '0')}.png`) });
}

async function nav(label: string) {
  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: label }).click();
}

test.beforeAll(async () => {
  dataDir = mkdtempSync(path.join(tmpdir(), 'breachframe-e2e-'));
  app = spawn(BIN, [], {
    env: {
      ...process.env,
      BREACHFRAME_DATA_DIR: dataDir,
      BREACHFRAME_CDP_PORT: String(PORT),
    },
    stdio: 'ignore',
  });
  await waitForCdp();
  browser = await chromium.connectOverCDP(`http://127.0.0.1:${PORT}`);
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    const pages = browser.contexts().flatMap((c) => c.pages());
    const p = pages.find((x) => !x.url().startsWith('devtools'));
    if (p) {
      page = p;
      break;
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  await page.setViewportSize({ width: 1440, height: 900 }).catch(() => undefined);
  await page.waitForLoadState('domcontentloaded');
  // Wait until React has mounted (and its keyboard listeners are attached).
  await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible({ timeout: 30_000 });
});

test.afterAll(async () => {
  await browser?.close().catch(() => undefined);
  app?.kill();
  await new Promise((r) => setTimeout(r, 800));
  rmSync(dataDir, { recursive: true, force: true });
});

test('starts with a real, empty database', async () => {
  await expect(page.getByRole('heading', { name: 'Security Dashboard' })).toBeVisible();
  await expect(page.getByText('Nothing analysed yet')).toBeVisible();
});

test('labs run the real engine and simulate an attacker', async () => {
  await nav('Simulation Labs');
  await expect(page.getByTestId('lab-k8s-ci-escalation')).toBeVisible();
  await shot('labs');
  await frame(400);
  await page.getByTestId('lab-k8s-ci-escalation').click();
  await expect(page.getByRole('heading', { name: 'CI service account to cluster-admin' })).toBeVisible();
  await expect(page.getByText('RBAC-020').first()).toBeVisible();
  await frame(400);

  await page.getByRole('tab', { name: 'Attack graph' }).click();
  await expect(page.locator('.react-flow__node').first()).toBeVisible();
  await frame(700);
  const paths = page.getByRole('complementary', { name: 'Attack paths' }).getByRole('button');
  await expect(paths.first()).toBeVisible();
  await paths.first().click();
  await expect(page.locator('.edge-hot').first()).toBeAttached();
  await shot('attack-path');
  await frame();

  await page.getByRole('button', { name: 'Simulate attacker' }).click();
  const sim = page.getByRole('region', { name: 'Simulation' });
  await expect(sim).toContainText('Blast radius from Pull-request pipeline');
  for (let step = 0; step <= 5; step++) {
    await page.getByRole('slider', { name: 'Step' }).fill(String(step));
    await frame(150);
  }
  await expect(sim).toContainText(/sensitive/);
  await shot('simulation');

  await page.getByRole('tab', { name: 'Fixed' }).click();
  await frame(700);
  await page.getByRole('tab', { name: 'Before & After' }).click();
  await expect(page.getByText(/Resolved \(\d+\)/)).toBeVisible();
  await frame(400);
});

test('importing a lab creates a project with two analyses and tracked findings', async () => {
  await nav('Simulation Labs');
  const back = page.getByRole('button', { name: 'Back to labs' });
  if (await back.isVisible()) await back.click();
  await page.getByTestId('lab-mcp-confused-deputy').click();
  await page.getByRole('button', { name: 'Import as project' }).click();
  await expect(page.getByRole('heading', { name: 'Before & After' })).toBeVisible();
  await expect(page.getByRole('img', { name: /Risk score \d+ of 100/ }).first()).toBeVisible();
  await shot('before-after');

  await nav('MCP Analyzer');
  await expect(page.getByRole('heading', { name: 'MCP Security Analyzer' })).toBeVisible();
  // Latest analysis is the fixed config; switch to the vulnerable one.
  const picker = page.getByRole('combobox', { name: 'Analysis' });
  const vulnerable = await picker.locator('option', { hasText: 'Vulnerable' }).getAttribute('value');
  await picker.selectOption(vulnerable!);
  await expect(page.getByText('auto-approved: run_command')).toBeVisible();
  await expect(page.getByText(/ghp_LabFakeToken0000000000/)).toHaveCount(0); // secrets stay redacted
  await shot('mcp');

  await nav('Findings');
  // The fixed run resolved the lab's findings: include resolved + absent ones.
  await page.getByRole('button', { name: 'Resolved', exact: true }).click();
  await page.getByLabel('History').check();
  const table = page.getByTestId('findings-table');
  await expect(table.locator('tbody tr').first()).toBeVisible();
  await shot('findings');
  await table.locator('tbody tr').first().click();
  const drawer = page.getByRole('dialog');
  await drawer.getByRole('radio', { name: 'Accepted risk' }).click();
  await expect(drawer.getByRole('radio', { name: 'Accepted risk' })).toHaveAttribute('aria-checked', 'true');
  await drawer.getByLabel('Notes').fill('Compensated by network isolation (e2e)');
  await drawer.getByRole('button', { name: 'Save notes' }).click();
  await page.keyboard.press('Escape');

  await nav('Reports');
  const frame = page.frameLocator('iframe[title="Report preview"]');
  await expect(frame.getByText('Security Analysis Report')).toBeVisible();
  await shot('report');

  await nav('Dashboard');
  await expect(page.getByText('Open findings by severity')).toBeVisible();
  await shot('dashboard');
});

test('keyboard shortcuts and command palette', async () => {
  await page.keyboard.press('Control+k');
  const palette = page.getByRole('dialog', { name: 'Command palette' });
  await expect(palette).toBeVisible();
  await palette.getByRole('textbox').fill('permis');
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Permission Auditor' }).or(page.getByText('No project selected'))).toBeVisible();
  if (await page.getByRole('heading', { name: 'Permission Auditor' }).isVisible()) await shot('permissions');
  await page.keyboard.press('Control+1');
  await expect(page.getByRole('heading', { name: 'Security Dashboard' })).toBeVisible();
  await page.keyboard.press('Shift+?');
  await expect(page.getByRole('dialog', { name: 'Keyboard shortcuts' })).toBeVisible();
  await page.keyboard.press('Escape');
});
