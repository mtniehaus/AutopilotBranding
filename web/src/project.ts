// A project in the web builder: the configuration plus the project's files (Assets\...), like a project folder
// created by New-AutopilotBrandingProject.  Files start as references to the default template published with the
// site and are replaced by files the user adds.  A project can be saved to and opened from a .zip file with the same
// layout as a project folder (AutopilotBranding.json + Assets\).

import { unzipSync } from 'fflate';
import { completeConfiguration, normalizePath, planOutput, type AssetLookup, type OutputPlan } from './config';
import { createIntuneWin, createZip, type IntuneWinResult } from './intunewin';
import type { Configuration, DataSource, SiteManifest, TaskDefinition } from './types';

export const CONFIG_FILE = 'AutopilotBranding.json';

export type ProjectFile = { kind: 'template'; path: string } | { kind: 'bytes'; data: Uint8Array };

export interface SiteData {
	manifest: SiteManifest;
	definitions: TaskDefinition[];
	templateConfiguration: Configuration;
	source: DataSource;
}

export async function loadSiteData(source: DataSource): Promise<SiteData> {
	const manifest = JSON.parse(await source.readText('manifest.json')) as SiteManifest;
	const definitions = JSON.parse(await source.readText('tasks.json')) as TaskDefinition[];
	for (const d of definitions) {
		for (const p of d.Parameters) {
			// PowerShell's ConvertTo-Json writes a one-element array default as an array, but be lenient
			if (p.Kind === 'StringArray' && p.DefaultValue !== null && !Array.isArray(p.DefaultValue)) p.DefaultValue = [String(p.DefaultValue)];
		}
	}
	const templateConfiguration = JSON.parse(await source.readText(`template/${CONFIG_FILE}`)) as Configuration;
	return { manifest, definitions, templateConfiguration, source };
}

export class Project implements AssetLookup {
	configuration: Configuration;
	/** Project files by normalized path (e.g. Assets/Autopilot.jpg); keys are looked up case-insensitively. */
	readonly files = new Map<string, ProjectFile>();

	constructor(readonly site: SiteData, configuration: Configuration) {
		this.configuration = completeConfiguration(configuration, site.definitions);
	}

	/** A new project from the default template: its configuration and all of its sample files. */
	static fromTemplate(site: SiteData): Project {
		const project = new Project(site, site.templateConfiguration);
		for (const path of site.manifest.TemplateFiles) {
			if (path.toLowerCase() !== CONFIG_FILE.toLowerCase()) project.files.set(normalizePath(path), { kind: 'template', path });
		}
		return project;
	}

	/** Opens a project .zip (AutopilotBranding.json + Assets\...), optionally inside a single top-level folder. */
	static fromZip(site: SiteData, zip: Uint8Array): Project {
		const entries = unzipSync(zip);
		const names = Object.keys(entries).filter((n) => !n.endsWith('/'));
		const configName = names.find((n) => n.split('/').pop()?.toLowerCase() === CONFIG_FILE.toLowerCase() && n.split('/').length <= 2);
		if (!configName) throw new Error(`The .zip file doesn't contain ${CONFIG_FILE}.`);
		const prefix = configName.slice(0, configName.length - CONFIG_FILE.length);
		const configuration = JSON.parse(new TextDecoder().decode(entries[configName]).replace(/^\uFEFF/, '')) as Configuration;
		const project = new Project(site, configuration);
		for (const name of names) {
			if (name === configName || !name.startsWith(prefix)) continue;
			project.files.set(normalizePath(name.slice(prefix.length)), { kind: 'bytes', data: entries[name] });
		}
		return project;
	}

	private key(path: string): string | undefined {
		const wanted = normalizePath(path).toLowerCase();
		for (const k of this.files.keys()) if (k.toLowerCase() === wanted) return k;
		return undefined;
	}

	hasFile(path: string): boolean {
		return this.key(path) !== undefined;
	}

	filesIn(folder: string): string[] {
		const prefix = normalizePath(folder).toLowerCase() + '/';
		return [...this.files.keys()].filter((k) => k.toLowerCase().startsWith(prefix)).sort();
	}

	isFolder(path: string): boolean {
		return this.filesIn(path).length > 0;
	}

	async readFile(path: string): Promise<Uint8Array> {
		const key = this.key(path);
		if (key === undefined) throw new Error(`File not found in the project: ${path}`);
		const file = this.files.get(key) as ProjectFile;
		return file.kind === 'bytes' ? file.data : this.site.source.readBytes(`template/${file.path}`);
	}

	/** Adds or replaces a file (path relative to the project, e.g. Assets/Logo.bmp). */
	setFile(path: string, data: Uint8Array): void {
		const existing = this.key(path);
		if (existing !== undefined) this.files.delete(existing);
		this.files.set(normalizePath(path), { kind: 'bytes', data });
	}

	/** Removes a file, or a folder with everything in it. */
	remove(path: string): void {
		const key = this.key(path);
		if (key !== undefined) this.files.delete(key);
		for (const k of this.filesIn(path)) this.files.delete(k);
	}

	/** Returns true if the file at path has exactly this content. */
	async sameContent(path: string, data: Uint8Array): Promise<boolean> {
		if (!this.hasFile(path)) return false;
		const existing = await this.readFile(path);
		if (existing.length !== data.length) return false;
		for (let i = 0; i < data.length; i++) if (existing[i] !== data[i]) return false;
		return true;
	}

	/** Saves the project as a .zip with the layout of a project folder. */
	async toZip(): Promise<Uint8Array> {
		const files = new Map<string, Uint8Array>();
		files.set(CONFIG_FILE, new TextEncoder().encode(JSON.stringify(this.configuration, null, 2) + '\n'));
		for (const path of [...this.files.keys()].sort()) files.set(path, await this.readFile(path));
		return createZip(files, 6);
	}

	plan(): OutputPlan {
		return planOutput(this.configuration, this.site.definitions, this, this.site.manifest.ModuleFiles, this.site.manifest.Runner);
	}

	/** The content of the output folder (what goes into the .intunewin), by relative path. */
	async outputFiles(plan: OutputPlan = this.plan()): Promise<Map<string, Uint8Array>> {
		const files = new Map<string, Uint8Array>();
		for (const file of plan.files) {
			if (file.from.kind === 'bytes') files.set(file.path, file.from.data);
			else if (file.from.kind === 'module') files.set(file.path, await this.site.source.readBytes(`module/${file.from.path}`));
			else files.set(file.path, await this.readFile(file.from.path));
		}
		return files;
	}

	/** Generates the .intunewin package (the setup file is the generic runner, AutopilotBranding.ps1). */
	async generate(): Promise<IntuneWinResult & { plan: OutputPlan }> {
		const plan = this.plan();
		const files = await this.outputFiles(plan);
		const result = await createIntuneWin(files, { setupFile: 'AutopilotBranding.ps1' });
		return { ...result, plan };
	}
}
