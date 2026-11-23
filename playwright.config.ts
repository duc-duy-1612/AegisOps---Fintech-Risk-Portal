import { existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { defineConfig, devices } from '@playwright/test';

const resolveLocalChromiumExecutable = (): string | undefined => {
  const localAppData = process.env.LOCALAPPDATA;
  if (localAppData) {
    const cacheDir = join(localAppData, 'ms-playwright');
    if (existsSync(cacheDir)) {
      const dirs = readdirSync(cacheDir)
        .filter((d) => d.startsWith('chromium-') && !d.includes('headless'))
        .sort()
        .reverse();
      for (const dir of dirs) {
        const winExe = join(cacheDir, dir, 'chrome-win64', 'chrome.exe');
        if (existsSync(winExe)) return winExe;
        const winExeLegacy = join(cacheDir, dir, 'chrome-win', 'chrome.exe');
        if (existsSync(winExeLegacy)) return winExeLegacy;
      }
    }
  }
  const edgeExe = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
  if (existsSync(edgeExe)) return edgeExe;
  return undefined;
};

const executablePath = resolveLocalChromiumExecutable();

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 45_000,
  expect: {
    timeout: 10_000,
  },
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:3100',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    launchOptions: executablePath ? { executablePath } : undefined,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: 'npx next start -p 3100 -H 127.0.0.1',
    url: 'http://127.0.0.1:3100/api/health',
    reuseExistingServer: false,
    timeout: 60_000,
    env: {
      ...process.env,
      AEGIS_E2E_DISABLE_EXTERNAL_AI: 'true',
      GEMINI_API_KEY: '',
    },
  },
});
