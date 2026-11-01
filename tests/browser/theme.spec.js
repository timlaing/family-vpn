const { test, expect } = require('@playwright/test');

const theme = page => page.locator('html');
const choice = page => page.getByRole('combobox', { name: 'Color theme' });

for (const preference of ['light', 'dark']) {
  test(`${preference} persists across reload and navigation`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: preference === 'light' ? 'dark' : 'light' });
    await page.goto('/');
    await choice(page).selectOption(preference);
    await expect(theme(page)).toHaveAttribute('data-theme', preference);
    await page.reload();
    await expect(choice(page)).toHaveValue(preference);
    await expect(theme(page)).toHaveAttribute('data-theme', preference);
    await page.goto('/login');
    await expect(choice(page)).toHaveValue(preference);
    await expect(theme(page)).toHaveAttribute('data-theme', preference);
    await page.emulateMedia({ colorScheme: preference });
    await page.emulateMedia({ colorScheme: preference === 'light' ? 'dark' : 'light' });
    await expect(theme(page)).toHaveAttribute('data-theme', preference);
  });
}

test('System follows live appearance changes and can be restored', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'light' });
  await page.goto('/');
  await expect(choice(page)).toHaveValue('system');
  await expect(theme(page)).toHaveAttribute('data-theme', 'light');
  await page.emulateMedia({ colorScheme: 'dark' });
  await expect(theme(page)).toHaveAttribute('data-theme', 'dark');
  await choice(page).selectOption('light');
  await choice(page).selectOption('system');
  await expect(theme(page)).toHaveAttribute('data-theme', 'dark');
  await page.reload();
  await expect(choice(page)).toHaveValue('system');
  await page.emulateMedia({ colorScheme: 'light' });
  await expect(theme(page)).toHaveAttribute('data-theme', 'light');
});

test('invalid stored preferences fall back to System', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('family-vpn-theme', 'invalid'));
  await page.emulateMedia({ colorScheme: 'light' });
  await page.goto('/');
  await expect(choice(page)).toHaveValue('system');
  await expect(theme(page)).toHaveAttribute('data-theme', 'light');
});

test('disabled storage allows session switching without errors', async ({ page }) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    Object.defineProperty(window, 'localStorage', { get() { throw new DOMException('Disabled', 'SecurityError'); } });
  });
  await page.emulateMedia({ colorScheme: 'light' });
  await page.goto('/');
  await expect(choice(page)).toHaveValue('system');
  await choice(page).selectOption('dark');
  await expect(theme(page)).toHaveAttribute('data-theme', 'dark');
  await choice(page).selectOption('light');
  await expect(theme(page)).toHaveAttribute('data-theme', 'light');
  expect(errors).toEqual([]);
});

for (const preference of ['light', 'dark']) {
  test(`${preference} header fits and upload buttons have readable contrast`, async ({ page }) => {
    await page.goto('/provisioning');
    await choice(page).selectOption(preference);
    await expect(page.locator('.app-header [data-theme-choice]')).toHaveCount(1);
    const select = await choice(page).boundingBox();
    const menu = await page.locator('.navigation summary').boundingBox();
    expect(select.height).toBeGreaterThanOrEqual(44);
    expect(Math.abs((select.y + select.height / 2) - (menu.y + menu.height / 2))).toBeLessThan(2);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const contrast = await page.locator('input[type=file]').first().evaluate(input => {
      const style = getComputedStyle(input, '::file-selector-button');
      const luminance = value => {
        const rgb = value.match(/[\d.]+/g).slice(0, 3).map(Number).map(v => v / 255)
          .map(v => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4);
        return rgb.reduce((sum, v, i) => sum + v * [.2126, .7152, .0722][i], 0);
      };
      // Dark mode uses a translucent surface, so composite it over the input background.
      const rgba = style.backgroundColor.match(/[\d.]+/g).map(Number);
      const base = getComputedStyle(input).backgroundColor.match(/[\d.]+/g).map(Number);
      const alpha = rgba[3] ?? 1;
      const background = `rgb(${rgba.slice(0, 3).map((v, i) => v * alpha + base[i] * (1 - alpha)).join(',')})`;
      const values = [luminance(style.color), luminance(background)].sort((a, b) => a - b);
      return (values[1] + .05) / (values[0] + .05);
    });
    expect(contrast).toBeGreaterThanOrEqual(4.5);
  });
}
