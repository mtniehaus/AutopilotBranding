// Command-line generator: builds an .intunewin with the same code as the web page, in Node (22 or later).
//   node dist-node/generate.mjs --data dist/data --out AutopilotBranding.intunewin
//        [--project project.zip] [--config AutopilotBranding.json] [--content content.zip]
// Without --project, the default template (from the data folder) is used; --config replaces its configuration.
// Used by CI to check web-generated packages with PowerShell and the SvRooij.ContentPrep module.

import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Project, loadSiteData } from '../src/project';
import type { Configuration, DataSource } from '../src/types';

function argument(name: string): string | undefined {
	const index = process.argv.indexOf(`--${name}`);
	return index >= 0 ? process.argv[index + 1] : undefined;
}

async function main(): Promise<void> {
	const dataFolder = argument('data') ?? 'dist/data';
	const out = argument('out') ?? 'AutopilotBranding.intunewin';
	const source: DataSource = {
		readText: (path) => readFile(join(dataFolder, path), 'utf8'),
		readBytes: async (path) => new Uint8Array(await readFile(join(dataFolder, path))),
	};
	const site = await loadSiteData(source);
	const projectZip = argument('project');
	const project = projectZip ? Project.fromZip(site, new Uint8Array(await readFile(projectZip))) : Project.fromTemplate(site);
	const configPath = argument('config');
	if (configPath) {
		const configuration = JSON.parse((await readFile(configPath, 'utf8')).replace(/^\uFEFF/, '')) as Configuration;
		project.configuration = new Project(site, configuration).configuration;
	}
	const result = await project.generate();
	await writeFile(out, result.package);
	const content = argument('content');
	if (content) await writeFile(content, result.contentZip);
	console.log(JSON.stringify({ package: out, size: result.package.length, files: result.plan.files.length, enabledTasks: result.plan.enabledTasks }, null, 2));
}

main().catch((error: unknown) => {
	console.error(error instanceof Error ? error.message : error);
	process.exit(1);
});
