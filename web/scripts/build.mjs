// Builds the static site into dist/ (app.js, index.html, styles.css) and the command-line generator into
// dist-node/.  The data the site loads (dist/data) is exported from the PowerShell module by Export-WebData.ps1.
import { build } from 'esbuild';
import { copyFile, mkdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
await mkdir(join(root, 'dist'), { recursive: true });

await build({
	entryPoints: [join(root, 'src/main.ts')],
	outfile: join(root, 'dist/app.js'),
	bundle: true,
	format: 'esm',
	platform: 'browser',
	target: ['es2022'],
	minify: true,
	sourcemap: true,
	logLevel: 'warning',
});
await copyFile(join(root, 'index.html'), join(root, 'dist/index.html'));
await copyFile(join(root, 'src/styles.css'), join(root, 'dist/styles.css'));

await build({
	entryPoints: [join(root, 'scripts/generate.ts')],
	outfile: join(root, 'dist-node/generate.mjs'),
	bundle: true,
	format: 'esm',
	platform: 'node',
	target: ['node22'],
	logLevel: 'warning',
});
console.log('Built dist/ and dist-node/generate.mjs');
