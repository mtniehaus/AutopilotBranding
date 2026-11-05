// Tests for the web builder's package generation, run with `npm test` after the data has been exported to dist/data
// (scripts/Export-WebData.ps1).  Packages are generated with the command-line generator (the same code as the page)
// and decoded independently here with node:crypto, so the Web Crypto code is checked against another implementation.
// CI additionally decodes them with PowerShell and compares them with a package made by SvRooij.ContentPrep.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { strToU8, zipSync } from 'fflate';
import { decode, tag } from './decode.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const data = join(root, 'dist', 'data');
const generator = join(root, 'dist-node', 'generate.mjs');
const temp = mkdtempSync(join(tmpdir(), 'ab-web-'));

function generate(args) {
	const out = join(temp, `package-${Math.random().toString(36).slice(2)}.intunewin`);
	const result = execFileSync(process.execPath, [generator, '--data', data, '--out', out, ...args], { encoding: 'utf8' });
	return { out, summary: JSON.parse(result) };
}

const manifest = JSON.parse(readFileSync(join(data, 'manifest.json'), 'utf8'));
const template = JSON.parse(readFileSync(join(data, 'template', 'AutopilotBranding.json'), 'utf8'));

test('default template: package decodes and has the runner, module, assets and configuration', () => {
	const { out, summary } = generate([]);
	const { entries } = decode(out);
	const names = Object.keys(entries);
	assert.deepEqual(entries['AutopilotBranding.ps1'], new Uint8Array(readFileSync(join(data, 'module', manifest.Runner))), 'runner is not the generic one');
	for (const file of manifest.ModuleFiles) {
		assert.ok(names.includes(`AutopilotBranding/${file}`), `module file ${file} missing`);
	}
	assert.ok(!names.some((n) => n.startsWith('AutopilotBranding/Template/')), 'the template was packaged');
	const configuration = JSON.parse(new TextDecoder().decode(entries['AutopilotBranding.json']));
	assert.equal(configuration.Tasks['Set-ABTheme'].Parameters.ThemePath, 'Assets\\Autopilot.theme');
	assert.equal(configuration.Tasks['Set-ABLanguage'].Parameters.LanguageXmlPath, '', 'file of a disabled task not cleared');
	assert.deepEqual(entries['Assets/Autopilot.theme'], new Uint8Array(readFileSync(join(data, 'template', 'Assets', 'Autopilot.theme'))));
	assert.ok(!names.includes('Assets/Language.xml'), 'file of a disabled task packaged');
	// Every file/folder parameter points at something in the package
	for (const entry of Object.values(configuration.Tasks)) {
		for (const value of Object.values(entry.Parameters)) {
			if (typeof value === 'string' && value.startsWith('Assets\\')) {
				const path = value.replace(/\\/g, '/');
				assert.ok(names.includes(path) || names.some((n) => n.startsWith(path + '/')), `${value} not in the package`);
			}
		}
	}
	assert.equal(summary.enabledTasks.length, Object.values(template.Tasks).filter((t) => t.Enabled).length);
});

test('a project .zip with added files and a folder is packaged with them', () => {
	const configuration = structuredClone(template);
	configuration.Tasks['Set-ABTheme'].Parameters.WallpaperPath = 'Assets/My Wallpaper.jpg';
	configuration.Tasks['Enable-ABUEV'].Enabled = true;
	configuration.Tasks['Enable-ABUEV'].Parameters.TemplateFolder = 'Assets\\My UEV';
	configuration.Tasks['Set-ABTimeZone'].Parameters.TimeZone = 'W. Europe Standard Time';
	const files = {
		'AutopilotBranding.json': strToU8(JSON.stringify(configuration)),
		'Assets/My Wallpaper.jpg': strToU8('my wallpaper'),
		'Assets/My UEV/One.xml': strToU8('<one/>'),
		'Assets/My UEV/Sub/Two.xml': strToU8('<two/>'),
	};
	for (const path of manifest.TemplateFiles.filter((p) => p.startsWith('Assets/'))) {
		files[path] = new Uint8Array(readFileSync(join(data, 'template', path)));
	}
	const projectZip = join(temp, 'project.zip');
	writeFileSync(projectZip, zipSync(files));

	const { out } = generate(['--project', projectZip]);
	const { entries } = decode(out);
	const packaged = JSON.parse(new TextDecoder().decode(entries['AutopilotBranding.json']));
	assert.equal(packaged.Tasks['Set-ABTheme'].Parameters.WallpaperPath, 'Assets\\My Wallpaper.jpg');
	assert.equal(new TextDecoder().decode(entries['Assets/My Wallpaper.jpg']), 'my wallpaper');
	assert.equal(packaged.Tasks['Enable-ABUEV'].Parameters.TemplateFolder, 'Assets\\My UEV');
	assert.equal(new TextDecoder().decode(entries['Assets/My UEV/Sub/Two.xml']), '<two/>');
	assert.equal(packaged.Tasks['Set-ABTimeZone'].Parameters.TimeZone, 'W. Europe Standard Time');
});

test('a configuration that refers to a missing file is refused', () => {
	const configuration = structuredClone(template);
	configuration.Tasks['Set-ABTheme'].Parameters.WallpaperPath = 'C:\\Users\\someone\\wallpaper.jpg';
	const path = join(temp, 'bad.json');
	writeFileSync(path, JSON.stringify(configuration));
	assert.throws(() => generate(['--config', path]), /WallpaperPath/);
});

test('packages are different each time (random keys and IV)', () => {
	const a = decode(generate([]).out).xml;
	const b = decode(generate([]).out).xml;
	assert.notEqual(tag(a, 'EncryptionKey'), tag(b, 'EncryptionKey'));
	assert.notEqual(tag(a, 'InitializationVector'), tag(b, 'InitializationVector'));
});
