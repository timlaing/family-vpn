const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: '.',
  testMatch: '*.spec.js',
  use: { baseURL: 'http://127.0.0.1:18500', trace: 'retain-on-failure' },
  projects: [
    { name: 'desktop', use: { browserName: 'chromium', viewport: { width: 1280, height: 800 } } },
    { name: 'mobile', use: { browserName: 'chromium', viewport: { width: 375, height: 812 }, isMobile: true, hasTouch: true } },
  ],
  webServer: {
    command: `${process.env.BROWSER_TEST_PYTHON || '../../.venv/bin/python'} serve.py`,
    url: 'http://127.0.0.1:18500/health',
    reuseExistingServer: false,
  },
});
