// Configuration handling, ported from the PowerShell builder (Module\AutopilotBranding\Public\Builder.ps1):
// Complete-ABConfiguration, ConvertTo-ABParameterValue, Test-ABConfiguration and the output layout of New-ABOutput.
// Keep the behavior in sync with the module.

import type { Configuration, ParameterDefinition, ParameterValue, Problem, TaskDefinition, TaskEntry } from './types';

export const CONFIGURATION_VERSION = 1;

/** Coerces a configuration value to the type expected by a task parameter (ConvertTo-ABParameterValue). */
export function toParameterValue(definition: ParameterDefinition, value: unknown): ParameterValue {
	switch (definition.Kind) {
		case 'Switch':
		case 'Boolean':
			if (value === null || value === undefined) return Boolean(definition.DefaultValue);
			if (typeof value === 'string') return ['true', '1', '$true'].includes(value.trim().toLowerCase());
			return Boolean(value);
		case 'StringArray': {
			if (value === null || value === undefined) return [];
			const items = Array.isArray(value) ? value : [value];
			return items
				.filter((item) => item !== null && item !== undefined)
				.flatMap((item) => String(item).split(/\r?\n/))
				.map((line) => line.trim())
				.filter((line) => line !== '');
		}
		case 'Integer': {
			if (value === null || value === undefined || String(value).trim() === '') return null;
			const number = Number(value);
			if (!Number.isInteger(number)) throw new Error(`${definition.Name}: ${String(value)} is not a whole number`);
			return number;
		}
		default:
			return value === null || value === undefined ? '' : String(value);
	}
}

function emptyEntry(enabled: boolean): TaskEntry {
	return { Enabled: enabled, Parameters: {} };
}

/**
 * Makes sure a configuration has an entry for every task and a value for every parameter (Complete-ABConfiguration).
 * Tasks that aren't in the configuration are added disabled; unknown tasks and parameters are kept.  The tasks are
 * reordered to match the module's run order.  Returns a new object.
 */
export function completeConfiguration(source: unknown, definitions: TaskDefinition[]): Configuration {
	const input = (source && typeof source === 'object' ? source : {}) as Record<string, unknown>;
	const existing = (input.Tasks && typeof input.Tasks === 'object' ? input.Tasks : {}) as Record<string, Partial<TaskEntry> | null>;
	const tasks: Record<string, TaskEntry> = {};
	for (const definition of definitions) {
		const entry = existing[definition.Name];
		const enabled = entry ? (entry.Enabled === undefined ? true : Boolean(entry.Enabled)) : false;
		const parameters = (entry && entry.Parameters && typeof entry.Parameters === 'object' ? entry.Parameters : {}) as Record<string, unknown>;
		const completed: Record<string, ParameterValue> = {};
		for (const p of definition.Parameters) {
			const value = Object.prototype.hasOwnProperty.call(parameters, p.Name) ? parameters[p.Name] : p.DefaultValue;
			completed[p.Name] = toParameterValue(p, value);
		}
		for (const [key, value] of Object.entries(parameters)) {
			if (!(key in completed)) completed[key] = value as ParameterValue;
		}
		tasks[definition.Name] = { Enabled: enabled, Parameters: completed };
	}
	for (const [key, value] of Object.entries(existing)) {
		if (!(key in tasks)) tasks[key] = (value as TaskEntry) ?? emptyEntry(false);
	}
	return {
		...input,
		Version: typeof input.Version === 'number' ? input.Version : CONFIGURATION_VERSION,
		Tasks: tasks,
	} as Configuration;
}

/** A new configuration with every task disabled and every parameter at its default value. */
export function newConfiguration(definitions: TaskDefinition[]): Configuration {
	const tasks: Record<string, TaskEntry> = {};
	for (const definition of definitions) tasks[definition.Name] = emptyEntry(false);
	return completeConfiguration({ Version: CONFIGURATION_VERSION, Description: 'Autopilot Branding configuration', Tasks: tasks }, definitions);
}

/** Normalizes a project-relative path: forward slashes, no leading ./ or slash. */
export function normalizePath(path: string): string {
	return path.replace(/\\/g, '/').replace(/^(\.\/)+/, '').replace(/^\/+/, '').replace(/\/+$/, '');
}

export function isRootedPath(path: string): boolean {
	return /^[A-Za-z]:[\\/]/.test(path) || /^[\\/]{2}/.test(path) || path.startsWith('/') || path.startsWith('%') || path.startsWith('$');
}

/** The files of a project (configuration-relative paths such as Assets/Autopilot.jpg), looked up case-insensitively. */
export interface AssetLookup {
	hasFile(path: string): boolean;
	/** Paths of the files in a folder (recursively), relative to the project. */
	filesIn(folder: string): string[];
}

function isEmpty(value: ParameterValue): boolean {
	return value === null || (typeof value === 'string' && value.trim() === '') || (Array.isArray(value) && value.length === 0);
}

/** Validates a configuration (Test-ABConfiguration), checking file and folder parameters against the project's files. */
export function validateConfiguration(configuration: Configuration, definitions: TaskDefinition[], assets: AssetLookup): Problem[] {
	const problems: Problem[] = [];
	const byName = new Map(definitions.map((d) => [d.Name, d]));
	for (const [taskName, entry] of Object.entries(configuration.Tasks)) {
		const definition = byName.get(taskName);
		if (!definition) {
			problems.push({ Severity: 'Warning', Task: taskName, Parameter: null, Message: 'Unknown task, it will be ignored.' });
			continue;
		}
		if (!entry.Enabled) continue;
		for (const key of Object.keys(entry.Parameters)) {
			if (!definition.Parameters.some((p) => p.Name === key)) {
				problems.push({ Severity: 'Warning', Task: taskName, Parameter: key, Message: 'Unknown parameter, it will be ignored.' });
			}
		}
		for (const p of definition.Parameters) {
			const value = entry.Parameters[p.Name] ?? null;
			if (p.Mandatory && isEmpty(value)) {
				problems.push({ Severity: 'Error', Task: taskName, Parameter: p.Name, Message: 'A value is required.' });
				continue;
			}
			if (p.ValidateSet && !isEmpty(value) && !p.ValidateSet.includes(String(value))) {
				problems.push({ Severity: 'Error', Task: taskName, Parameter: p.Name, Message: `Value must be one of: ${p.ValidateSet.join(', ')}` });
			}
			if (p.AssetKind && !isEmpty(value)) {
				const path = String(value);
				if (isRootedPath(path)) {
					problems.push({ Severity: 'Error', Task: taskName, Parameter: p.Name, Message: `${path} isn't in the project; add the ${p.AssetKind.toLowerCase()} to the project's Assets.` });
				} else if (p.AssetKind === 'File' && !assets.hasFile(path)) {
					problems.push({ Severity: 'Error', Task: taskName, Parameter: p.Name, Message: `File not found in the project: ${normalizePath(path)}` });
				} else if (p.AssetKind === 'Folder' && assets.filesIn(path).length === 0) {
					problems.push({ Severity: 'Error', Task: taskName, Parameter: p.Name, Message: `Folder not found (or empty) in the project: ${normalizePath(path)}` });
				}
			}
		}
	}
	return problems;
}

/** One file of the output folder: either the bytes, or where to read them from. */
export interface OutputFile {
	path: string;
	from: { kind: 'module'; path: string } | { kind: 'project'; path: string } | { kind: 'bytes'; data: Uint8Array };
}

export interface OutputPlan {
	files: OutputFile[];
	configuration: Configuration;
	enabledTasks: string[];
}

/**
 * Plans the output folder (the content of the .intunewin) like New-ABOutput:
 *   AutopilotBranding.ps1    the generic runner script from the module
 *   AutopilotBranding\       the module (without its project template)
 *   Assets\                  the files and folders used by enabled tasks, named by their leaf name (made unique)
 *   AutopilotBranding.json   the configuration, with file and folder parameters pointing at Assets\...; those of
 *                            disabled tasks are cleared, so nothing refers outside the package
 */
export function planOutput(configuration: Configuration, definitions: TaskDefinition[], assets: AssetLookup, moduleFiles: string[], runner: string): OutputPlan {
	const errors = validateConfiguration(configuration, definitions, assets).filter((p) => p.Severity === 'Error');
	if (errors.length > 0) {
		throw new Error('The configuration has errors:\n' + errors.map((e) => `  ${e.Task} -${e.Parameter}: ${e.Message}`).join('\n'));
	}

	const files: OutputFile[] = [];
	files.push({ path: 'AutopilotBranding.ps1', from: { kind: 'module', path: runner } });
	for (const path of moduleFiles) {
		files.push({ path: `AutopilotBranding/${path}`, from: { kind: 'module', path } });
	}

	const output = JSON.parse(JSON.stringify(configuration)) as Configuration;
	const sourceToName = new Map<string, string>();
	const usedNames = new Set<string>();
	for (const definition of definitions) {
		const entry = configuration.Tasks[definition.Name];
		if (!entry) continue;
		for (const p of definition.Parameters.filter((q) => q.AssetKind)) {
			const value = entry.Parameters[p.Name];
			if (!entry.Enabled || value === null || value === undefined || String(value).trim() === '') {
				if (p.Name in output.Tasks[definition.Name].Parameters) output.Tasks[definition.Name].Parameters[p.Name] = '';
				continue;
			}
			const source = normalizePath(String(value));
			const sourceKey = source.toLowerCase();
			let name = sourceToName.get(sourceKey);
			if (name === undefined) {
				const leaf = source.split('/').pop() as string;
				name = leaf;
				const dot = leaf.lastIndexOf('.');
				const stem = dot > 0 ? leaf.slice(0, dot) : leaf;
				const extension = dot > 0 ? leaf.slice(dot) : '';
				for (let i = 2; usedNames.has(name.toLowerCase()); i++) name = `${stem}_${i}${extension}`;
				usedNames.add(name.toLowerCase());
				sourceToName.set(sourceKey, name);
				if (p.AssetKind === 'Folder') {
					for (const file of assets.filesIn(source)) {
						const relative = file.slice(source.length + 1);
						files.push({ path: `Assets/${name}/${relative}`, from: { kind: 'project', path: file } });
					}
				} else {
					files.push({ path: `Assets/${name}`, from: { kind: 'project', path: source } });
				}
			}
			output.Tasks[definition.Name].Parameters[p.Name] = `Assets\\${name}`;
		}
	}

	files.push({ path: 'AutopilotBranding.json', from: { kind: 'bytes', data: new TextEncoder().encode(JSON.stringify(output, null, 2) + '\n') } });
	checkSelfContained(files, output, definitions);
	return {
		files,
		configuration: output,
		enabledTasks: definitions.filter((d) => configuration.Tasks[d.Name]?.Enabled).map((d) => d.Name),
	};
}

/** Test-ABOutputSelfContained: every file and folder parameter must be relative and present in the output. */
function checkSelfContained(files: OutputFile[], output: Configuration, definitions: TaskDefinition[]): void {
	const paths = new Set(files.map((f) => f.path.toLowerCase()));
	const problems: string[] = [];
	for (const definition of definitions) {
		const entry = output.Tasks[definition.Name];
		if (!entry) continue;
		for (const p of definition.Parameters.filter((q) => q.AssetKind)) {
			const value = entry.Parameters[p.Name];
			if (value === null || value === undefined || String(value) === '') continue;
			const path = normalizePath(String(value));
			if (isRootedPath(String(value)) || path.split('/').includes('..')) {
				problems.push(`${definition.Name} -${p.Name}: ${String(value)} is not a path inside the package`);
			} else if (!paths.has(path.toLowerCase()) && ![...paths].some((f) => f.startsWith(path.toLowerCase() + '/'))) {
				problems.push(`${definition.Name} -${p.Name}: ${String(value)} not found in the package`);
			}
		}
	}
	if (problems.length > 0) throw new Error("The output isn't self-contained:\n  " + problems.join('\n  '));
}
