// End-to-end test of the web builder in a real browser (Playwright + Chromium), after `npm run build` and the data
// export.  Serves dist/ on localhost, edits a configuration through the UI (text, list, file and folder uploads,
// replace confirmation), generates the .intunewin and decodes the download, and saves and reopens the project.
//   node test/e2e.mjs [--screenshot path.png]
// Playwright isn't a dependency of the site; install it (or use a preinstalled one) to run this test.

import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decode } from './decode.mjs';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');

const root = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const temp = mkdtempSync(join(tmpdir(), 'ab-e2e-'));
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.map': 'application/json' };

const server = createServer((request, response) => {
	const path = normalize(decodeURIComponent(new URL(request.url, 'http://localhost').pathname)).replace(/^([/\\])+/, '');
	const file = join(root, path === '' ? 'index.html' : path);
	if (!file.startsWith(root)) return response.writeHead(403).end();
	try {
		const body = readFileSync(file);
		response.writeHead(200, { 'Content-Type': types[extname(file)] ?? 'application/octet-stream' }).end(body);
	} catch {
		response.writeHead(404).end();
	}
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const url = `http://localhost:${server.address().port}/`;

const browser = await chromium.launch();
const page = await browser.newPage({ acceptDownloads: true, viewport: { width: 1400, height: 900 } });
const errors = [];
page.on('pageerror', (error) => errors.push(String(error)));
page.on('console', (message) => message.type() === 'error' && errors.push(message.text()));

const steps = [];
async function step(name, action) {
	await action();
	steps.push(name);
	console.log(`ok - ${name}`);
}

try {
	const tasks = JSON.parse(readFileSync(join(root, 'data', 'tasks.json'), 'utf8'));
	await page.goto(url);
	await step('page loads the task list', async () => {
		await page.waitForFunction((count) => document.querySelectorAll('#task-list li').length === count, tasks.length);
	});

	await step('header shows the module version', async () => {
		const manifest = JSON.parse(readFileSync(join(root, 'data', 'manifest.json'), 'utf8'));
		assert.equal(await page.textContent('#app-version'), `v${manifest.ModuleVersion}`);
	});

	await step('text parameter edit', async () => {
		await page.click('#task-list li[data-task="Set-ABRegisteredOwner"]');
		await page.fill('[data-parameter="Owner"] input', 'E2E Owner');
	});

	await step('list parameter edit', async () => {
		await page.click('#task-list li[data-task="Install-ABWinGetPackages"]');
		await page.fill('[data-parameter="PackageIds"] textarea', 'Mozilla.Firefox\n\n  Google.Chrome  ');
	});

	await step('file upload adds the file to Assets and sets the parameter', async () => {
		await page.click('#task-list li[data-task="Set-ABTheme"]');
		await page.setInputFiles('[data-parameter="WallpaperPath"] input[type="file"]', { name: 'E2E Wallpaper.jpg', mimeType: 'image/jpeg', buffer: Buffer.from('e2e wallpaper') });
		await page.waitForFunction(() => document.querySelector('[data-parameter="WallpaperPath"] input[type="text"]')?.value === 'Assets/E2E Wallpaper.jpg');
		assert.match(await page.textContent('[data-parameter="WallpaperPath"] .asset-state'), /In the project/);
	});

	await step('uploading a different file with an existing name asks before replacing (declined, then accepted)', async () => {
		page.once('dialog', (dialog) => dialog.dismiss());
		await page.setInputFiles('[data-parameter="WallpaperPath"] input[type="file"]', { name: 'Autopilot.jpg', mimeType: 'image/jpeg', buffer: Buffer.from('a different Autopilot.jpg') });
		await page.waitForTimeout(300);
		assert.equal(await page.inputValue('[data-parameter="WallpaperPath"] input[type="text"]'), 'Assets/E2E Wallpaper.jpg');
		page.once('dialog', (dialog) => dialog.accept());
		await page.setInputFiles('[data-parameter="WallpaperPath"] input[type="file"]', { name: 'Autopilot.jpg', mimeType: 'image/jpeg', buffer: Buffer.from('a different Autopilot.jpg') });
		await page.waitForFunction(() => document.querySelector('[data-parameter="WallpaperPath"] input[type="text"]')?.value === 'Assets/Autopilot.jpg');
	});

	await step('folder upload', async () => {
		await page.click('#task-list li[data-task="Enable-ABUEV"]');
		await page.check('#task-list li[data-task="Enable-ABUEV"] input[type="checkbox"]');
		const folder = join(temp, 'E2E Templates');
		mkdirSync(join(folder, 'Sub'), { recursive: true });
		writeFileSync(join(folder, 'One.xml'), '<one/>');
		writeFileSync(join(folder, 'Sub', 'Two.xml'), '<two/>');
		await page.setInputFiles('[data-parameter="TemplateFolder"] input[type="file"]', folder);
		await page.waitForFunction(() => document.querySelector('[data-parameter="TemplateFolder"] input[type="text"]')?.value === 'Assets/E2E Templates');
	});

	await step('validate reports no problems', async () => {
		await page.click('#validate');
		await page.waitForSelector('dialog[open]');
		assert.match(await page.textContent('#dialog-body'), /No problems found/);
		await page.click('dialog button');
	});

	let packagePath;
	await step('generate downloads a valid .intunewin with the edits', async () => {
		const [download] = await Promise.all([page.waitForEvent('download'), page.click('#generate')]);
		assert.equal(download.suggestedFilename(), 'AutopilotBranding.intunewin');
		packagePath = join(temp, 'web.intunewin');
		await download.saveAs(packagePath);
		await page.waitForSelector('dialog[open]');
		await page.click('dialog button');
		const { entries } = decode(packagePath);
		const configuration = JSON.parse(new TextDecoder().decode(entries['AutopilotBranding.json']));
		assert.equal(configuration.Tasks['Set-ABRegisteredOwner'].Parameters.Owner, 'E2E Owner');
		assert.deepEqual(configuration.Tasks['Install-ABWinGetPackages'].Parameters.PackageIds, ['Mozilla.Firefox', 'Google.Chrome']);
		assert.equal(configuration.Tasks['Set-ABTheme'].Parameters.WallpaperPath, 'Assets\\Autopilot.jpg');
		assert.equal(new TextDecoder().decode(entries['Assets/Autopilot.jpg']), 'a different Autopilot.jpg');
		assert.equal(configuration.Tasks['Enable-ABUEV'].Parameters.TemplateFolder, 'Assets\\E2E Templates');
		assert.equal(new TextDecoder().decode(entries['Assets/E2E Templates/Sub/Two.xml']), '<two/>');
	});

	await step('save the project and open it again', async () => {
		const [download] = await Promise.all([page.waitForEvent('download'), page.click('#save-project')]);
		const projectPath = join(temp, 'project.zip');
		await download.saveAs(projectPath);
		await page.click('#new-project');
		await page.click('#task-list li[data-task="Set-ABRegisteredOwner"]');
		assert.equal(await page.inputValue('[data-parameter="Owner"] input'), 'Autopilot User');
		await page.setInputFiles('#open-input', projectPath);
		await page.waitForFunction(() => document.querySelector('[data-parameter="Owner"] input')?.value === 'E2E Owner');
		await page.click('#show-files');
		assert.match(await page.textContent('.files-table'), /Assets\/E2E Templates\/Sub\/Two\.xml/);
	});

	const screenshot = process.argv.includes('--screenshot') ? process.argv[process.argv.indexOf('--screenshot') + 1] : null;
	if (screenshot) {
		await page.click('#task-list li[data-task="Set-ABTheme"]');
		await page.screenshot({ path: screenshot });
	}
	assert.deepEqual(errors, [], `Errors in the page: ${errors.join('; ')}`);
	console.log(`\n${steps.length} steps passed`);
} finally {
	await browser.close();
	server.close();
}
