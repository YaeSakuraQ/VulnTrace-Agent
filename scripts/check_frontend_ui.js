const { chromium } = require('/root/Desktop/Agent Project/frontend/node_modules/playwright');

async function main() {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 960 } });
  const errors = [];

  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  page.on('console', (message) => {
    if (message.type() === 'error') {
      const text = message.text();
      if (text.includes('Failed to load resource: the server responded with a status of 404')) {
        return;
      }
      errors.push(`console: ${text}`);
    }
  });

  await page.goto('http://127.0.0.1:4173/', { waitUntil: 'networkidle' });
  await page.waitForSelector('text=创建测试任务');
  await page.waitForSelector('text=任务总览');

  const taskName = `ui-smoke-${Date.now()}`;
  await page.locator('input[placeholder*="DVWA Web 检查"]').fill(taskName);
  await page.locator('input[placeholder*="127.0.0.1"]').fill('127.0.0.1');
  await page.locator('input[placeholder*="80,443,8080"]').fill('8000');
  await page.getByRole('button', { name: '创建任务' }).click();

  await page.waitForURL(/\/tasks\/.+/, { timeout: 15000 });
  await page.waitForSelector(`text=${taskName}`);
  await page.waitForSelector('.n-tabs-tab');
  await page.locator('.n-tabs-tab', { hasText: '活动' }).click();
  await page.waitForSelector('text=执行日志');
  await page.locator('.n-tabs-tab', { hasText: '审批' }).click();
  await page.waitForSelector('text=高风险审批');

  await page.goto('http://127.0.0.1:4173/tasks/c52678c4-8263-4e03-8ef1-0f1c5124ffd6', { waitUntil: 'networkidle' });
  await page.locator('.n-tabs-tab', { hasText: '报告' }).click();
  await page.waitForSelector('text=PoC 链路');
  await page.waitForSelector('text=DVWA File Inclusion low-level PoC');
  await page.waitForSelector('text=渲染后的 Markdown 报告');

  if (errors.length) {
    throw new Error(errors.join('\n'));
  }

  console.log(JSON.stringify({
    createdTask: taskName,
    finalUrl: page.url(),
    checks: [
      'homepage loaded',
      'task created from form',
      'task detail tabs rendered',
      'existing report page rendered',
    ],
  }, null, 2));

  await browser.close();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
