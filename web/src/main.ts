// The web builder UI: the same model as Show-AutopilotBrandingBuilder (tasks on the left, parameters on the right),
// working on a Project (configuration + files) entirely in the browser.

import { toParameterValue, validateConfiguration } from './config';
import { CONFIG_FILE, Project, loadSiteData, type SiteData } from './project';
import type { Configuration, DataSource, ParameterDefinition, ParameterValue, Problem, TaskDefinition } from './types';

const fetchSource: DataSource = {
	async readText(path) {
		const response = await fetch(`data/${path}`);
		if (!response.ok) throw new Error(`Unable to load data/${path} (${response.status})`);
		return response.text();
	},
	async readBytes(path) {
		const response = await fetch(`data/${path}`);
		if (!response.ok) throw new Error(`Unable to load data/${path} (${response.status})`);
		return new Uint8Array(await response.arrayBuffer());
	},
};

let site: SiteData;
let project: Project;
let projectName = 'New project';
let selected: string | 'files' = '';
let dirty = false;

function $(id: string): HTMLElement {
	return document.getElementById(id) as HTMLElement;
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> & { className?: string } = {}, ...children: (Node | string)[]): HTMLElementTagNameMap[K] {
	const element = document.createElement(tag);
	Object.assign(element, props);
	for (const child of children) element.append(child);
	return element;
}

function setStatus(text: string, isError = false): void {
	const status = $('status');
	status.textContent = text;
	status.className = isError ? 'error' : '';
}

function setDirty(value = true): void {
	dirty = value;
	$('project-name').textContent = projectName + (dirty ? ' (unsaved changes)' : '');
}

function showDialog(title: string, body: Node | string): void {
	$('dialog-title').textContent = title;
	const container = $('dialog-body');
	container.replaceChildren(typeof body === 'string' ? el('p', { textContent: body }) : body);
	($('dialog') as HTMLDialogElement).showModal();
}

function problemsList(problems: Problem[]): HTMLElement {
	return el('ul', {}, ...problems.map((p) => el('li', { className: p.Severity, textContent: `${p.Task}${p.Parameter ? ' -' + p.Parameter : ''}: ${p.Message}` })));
}

function download(name: string, data: Uint8Array, type = 'application/octet-stream'): void {
	const url = URL.createObjectURL(new Blob([data as BlobPart], { type }));
	const a = el('a', { href: url, download: name });
	document.body.append(a);
	a.click();
	a.remove();
	setTimeout(() => URL.revokeObjectURL(url), 30000);
}

function formatSize(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
	return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function formatValue(value: ParameterValue): string {
	if (value === null || value === undefined) return '';
	if (Array.isArray(value)) return value.join(', ');
	return String(value);
}

async function busy<T>(message: string, action: () => Promise<T>): Promise<T | undefined> {
	const buttons = document.querySelectorAll<HTMLButtonElement>('.toolbar button');
	buttons.forEach((b) => (b.disabled = true));
	setStatus(message);
	try {
		return await action();
	} catch (error) {
		setStatus(String((error as Error).message ?? error), true);
		showDialog('Something went wrong', String((error as Error).message ?? error));
		return undefined;
	} finally {
		buttons.forEach((b) => (b.disabled = false));
	}
}

function confirmDiscard(): boolean {
	return !dirty || confirm('Discard the unsaved changes to the current project?');
}

// ---------------------------------------------------------------- task list

function errorsByTask(): Set<string> {
	return new Set(validateConfiguration(project.configuration, site.definitions, project).filter((p) => p.Severity === 'Error').map((p) => p.Task));
}

function renderTaskList(): void {
	const list = $('task-list');
	const withErrors = errorsByTask();
	list.replaceChildren(
		...site.definitions.map((definition) => {
			const entry = project.configuration.Tasks[definition.Name];
			const checkbox = el('input', { type: 'checkbox', checked: entry.Enabled, title: 'Run this task' });
			checkbox.setAttribute('aria-label', `Run ${definition.Name}`);
			checkbox.addEventListener('click', (e) => e.stopPropagation());
			checkbox.addEventListener('change', () => setEnabled(definition.Name, checkbox.checked));
			const item = el(
				'li',
				{ className: [selected === definition.Name ? 'selected' : '', entry.Enabled && withErrors.has(definition.Name) ? 'has-error' : ''].join(' ').trim() },
				checkbox,
				el('span', {}, el('span', { className: 'task-name', textContent: definition.Name }), el('span', { className: 'task-synopsis', textContent: definition.Synopsis })),
			);
			item.dataset.task = definition.Name;
			item.addEventListener('click', () => select(definition.Name));
			return item;
		}),
	);
	$('show-files').classList.toggle('selected', selected === 'files');
	const enabled = site.definitions.filter((d) => project.configuration.Tasks[d.Name].Enabled).length;
	setStatus(`${enabled} of ${site.definitions.length} tasks enabled.  Everything runs in your browser; your files are never uploaded.`);
}

function setEnabled(name: string, enabled: boolean): void {
	project.configuration.Tasks[name].Enabled = enabled;
	setDirty();
	renderTaskList();
	if (selected === name) renderDetails();
}

function select(name: string | 'files'): void {
	selected = name;
	renderTaskList();
	renderDetails();
}

// ---------------------------------------------------------------- details

function setParameter(task: string, definition: ParameterDefinition, value: unknown): void {
	try {
		project.configuration.Tasks[task].Parameters[definition.Name] = toParameterValue(definition, value);
	} catch {
		return; // e.g. a partially typed number; keep the previous value
	}
	setDirty();
	renderTaskList();
}

function renderDetails(): void {
	const details = $('details');
	if (selected === 'files') {
		details.replaceChildren(renderFiles());
		return;
	}
	const definition = site.definitions.find((d) => d.Name === selected);
	if (!definition) {
		details.replaceChildren(el('p', { className: 'placeholder', textContent: 'Select a task.' }));
		return;
	}
	const entry = project.configuration.Tasks[definition.Name];
	const run = el('input', { type: 'checkbox', checked: entry.Enabled });
	run.addEventListener('change', () => setEnabled(definition.Name, run.checked));
	const parts: Node[] = [
		el('h2', { textContent: definition.Name }),
		el('p', { className: 'synopsis', textContent: definition.Synopsis }),
	];
	if (definition.Description) parts.push(el('p', { className: 'description', textContent: definition.Description }));
	parts.push(el('label', { className: 'run-task' }, run, 'Run this task'));
	parts.push(el('h3', { textContent: 'Parameters' }));
	if (definition.Parameters.length === 0) parts.push(el('p', { className: 'placeholder', textContent: 'This task has no parameters.' }));
	for (const p of definition.Parameters) parts.push(renderParameter(definition, p));
	details.replaceChildren(...parts);
}

function renderParameter(task: TaskDefinition, p: ParameterDefinition): HTMLElement {
	const value = project.configuration.Tasks[task.Name].Parameters[p.Name] ?? p.DefaultValue;
	const head = el('div', { className: 'param-head' }, el('span', { className: 'param-name', textContent: `-${p.Name}` }), el('span', { className: 'param-type', textContent: `[${p.TypeName}]${p.AssetKind ? ' (' + p.AssetKind.toLowerCase() + ')' : ''}` }));
	if (p.Mandatory) head.append(el('span', { className: 'param-required', textContent: 'required' }));
	const box = el('div', { className: 'param' }, head);
	box.dataset.parameter = p.Name;
	if (p.HelpText) box.append(el('p', { className: 'param-help', textContent: p.HelpText }));

	if (p.Kind === 'Boolean' || p.Kind === 'Switch') {
		const checkbox = el('input', { type: 'checkbox', checked: Boolean(value) });
		checkbox.addEventListener('change', () => setParameter(task.Name, p, checkbox.checked));
		box.append(el('label', {}, checkbox, ' Enabled'));
	} else if (p.ValidateSet) {
		const select = el('select', {}, ...p.ValidateSet.map((option) => el('option', { value: option, textContent: option, selected: option === value })));
		select.addEventListener('change', () => setParameter(task.Name, p, select.value));
		box.append(select);
	} else if (p.Kind === 'StringArray') {
		const textarea = el('textarea', { value: (Array.isArray(value) ? value : []).join('\n'), spellcheck: false });
		textarea.placeholder = 'One value per line';
		textarea.addEventListener('input', () => setParameter(task.Name, p, textarea.value));
		box.append(textarea);
	} else if (p.AssetKind) {
		box.append(...renderAssetEditor(task, p, String(value ?? '')));
	} else {
		const input = el('input', { type: p.Kind === 'Integer' ? 'number' : 'text', value: value === null ? '' : String(value) });
		input.addEventListener('input', () => setParameter(task.Name, p, input.value));
		box.append(input);
	}

	const defaultText = formatValue(p.DefaultValue);
	if (defaultText && p.Kind !== 'Switch') box.append(el('div', { className: 'param-default', textContent: `Default: ${defaultText}` }));
	return box;
}

function assetState(p: ParameterDefinition, value: string): HTMLElement {
	const state = el('div', { className: 'asset-state' });
	if (!value.trim()) return state;
	const exists = p.AssetKind === 'Folder' ? project.isFolder(value) : project.hasFile(value);
	state.className = `asset-state ${exists ? 'ok' : 'missing'}`;
	state.textContent = exists ? (p.AssetKind === 'Folder' ? `In the project (${project.filesIn(value).length} files)` : 'In the project') : `Not in the project; add the ${p.AssetKind?.toLowerCase()}`;
	return state;
}

function renderAssetEditor(task: TaskDefinition, p: ParameterDefinition, value: string): HTMLElement[] {
	const input = el('input', { type: 'text', value, spellcheck: false });
	let state = assetState(p, value);
	input.addEventListener('input', () => {
		setParameter(task.Name, p, input.value);
		const updated = assetState(p, input.value);
		state.replaceWith(updated);
		state = updated;
	});
	const picker = el('input', { type: 'file', hidden: true });
	if (p.AssetKind === 'Folder') {
		picker.multiple = true;
		picker.setAttribute('webkitdirectory', '');
	}
	const button = el('button', { type: 'button', textContent: p.AssetKind === 'Folder' ? 'Add folder…' : 'Add file…' });
	button.addEventListener('click', () => picker.click());
	picker.addEventListener('change', async () => {
		const files = [...(picker.files ?? [])];
		picker.value = '';
		if (files.length === 0) return;
		const relative = p.AssetKind === 'Folder' ? await addFolder(files) : await addFile(files[0]);
		if (relative) {
			setParameter(task.Name, p, relative);
			renderDetails();
		}
	});
	return [el('div', { className: 'asset-row' }, input, button, picker), state];
}

/** Adds a file to the project's Assets folder (confirming before replacing a different file); returns its path. */
export async function addFile(file: File): Promise<string | undefined> {
	const target = `Assets/${file.name}`;
	const data = new Uint8Array(await file.arrayBuffer());
	if (project.hasFile(target)) {
		if (await project.sameContent(target, data)) {
			setStatus(`Using the identical ${target} already in the project`);
			return target;
		}
		if (!confirm(`${target} already exists in the project and is different from the selected file.\n\nReplace it with ${file.name}?`)) {
			setStatus('Not changed');
			return undefined;
		}
	}
	project.setFile(target, data);
	setDirty();
	setStatus(`Added ${target} (${formatSize(data.length)})`);
	return target;
}

/** Adds a folder (from a directory picker) to the project's Assets folder; returns its path. */
async function addFolder(files: File[]): Promise<string | undefined> {
	const relativePath = (f: File) => ((f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name).replace(/\\/g, '/');
	const folderName = relativePath(files[0]).split('/')[0];
	const target = `Assets/${folderName}`;
	if (project.isFolder(target) && !confirm(`${target} already exists in the project.\n\nReplace it with the selected folder (${files.length} files)?`)) {
		setStatus('Not changed');
		return undefined;
	}
	project.remove(target);
	for (const file of files) {
		project.setFile(`Assets/${relativePath(file)}`, new Uint8Array(await file.arrayBuffer()));
	}
	setDirty();
	setStatus(`Added ${target} (${files.length} files)`);
	return target;
}

function renderFiles(): HTMLElement {
	const section = el('div');
	section.append(
		el('h2', { textContent: 'Project files' }),
		el('p', { className: 'description', textContent: 'The files in the project (its Assets folder). Files from the default template stay as they are until you replace them. When you generate, only the files used by enabled tasks go into the package.' }),
	);
	const picker = el('input', { type: 'file', multiple: true, hidden: true });
	const add = el('button', { type: 'button', textContent: 'Add files to Assets…' });
	add.addEventListener('click', () => picker.click());
	picker.addEventListener('change', async () => {
		for (const file of [...(picker.files ?? [])]) await addFile(file);
		picker.value = '';
		renderDetails();
		renderTaskList();
	});
	section.append(el('p', {}, add, picker));

	const used = new Set<string>();
	for (const d of site.definitions) {
		for (const p of d.Parameters.filter((q) => q.AssetKind)) {
			const v = project.configuration.Tasks[d.Name].Parameters[p.Name];
			if (typeof v === 'string' && v) used.add(v.replace(/\\/g, '/').toLowerCase());
		}
	}
	const table = el('table', { className: 'files-table' }, el('thead', {}, el('tr', {}, el('th', { textContent: 'File' }), el('th', { textContent: 'Origin' }), el('th', { textContent: 'Size' }), el('th'))));
	const body = el('tbody');
	for (const [path, file] of [...project.files.entries()].sort(([a], [b]) => a.localeCompare(b))) {
		const remove = el('button', { type: 'button', className: 'link', textContent: 'Remove' });
		remove.addEventListener('click', () => {
			project.remove(path);
			setDirty();
			renderDetails();
			renderTaskList();
		});
		const save = el('button', { type: 'button', className: 'link', textContent: 'Download' });
		save.addEventListener('click', async () => download(path.split('/').pop() as string, await project.readFile(path)));
		const isUsed = [...used].some((u) => path.toLowerCase() === u || path.toLowerCase().startsWith(u + '/'));
		body.append(
			el('tr', {}, el('td', { textContent: path + (isUsed ? '' : '  (not used)') }), el('td', { className: 'origin', textContent: file.kind === 'template' ? 'template' : 'added' }), el('td', { className: 'size', textContent: file.kind === 'bytes' ? formatSize(file.data.length) : '' }), el('td', {}, save, remove)),
		);
	}
	table.append(body);
	section.append(table);
	return section;
}

// ---------------------------------------------------------------- toolbar

function setProject(next: Project, name: string): void {
	project = next;
	projectName = name;
	setDirty(false);
	if (!selected || (selected !== 'files' && !site.definitions.some((d) => d.Name === selected))) selected = site.definitions[0]?.Name ?? '';
	renderTaskList();
	renderDetails();
}

function wireToolbar(): void {
	$('new-project').addEventListener('click', () => {
		if (confirmDiscard()) setProject(Project.fromTemplate(site), 'New project');
	});

	const openInput = $('open-input') as HTMLInputElement;
	$('open-project').addEventListener('click', () => {
		if (confirmDiscard()) openInput.click();
	});
	openInput.addEventListener('change', async () => {
		const file = openInput.files?.[0];
		openInput.value = '';
		if (!file) return;
		await busy(`Opening ${file.name}…`, async () => {
			const data = new Uint8Array(await file.arrayBuffer());
			if (file.name.toLowerCase().endsWith('.json')) {
				// A configuration only: keep the current files (start from the template's if needed)
				const configuration = JSON.parse(new TextDecoder().decode(data).replace(/^\uFEFF/, '')) as Configuration;
				const next = Project.fromTemplate(site);
				for (const [path, f] of project.files) if (f.kind === 'bytes') next.files.set(path, f);
				next.configuration = new Project(site, configuration).configuration;
				setProject(next, file.name);
				setStatus(`Opened configuration ${file.name}; files referenced by it must be in the project (see Project files)`);
			} else {
				setProject(Project.fromZip(site, data), file.name.replace(/\.zip$/i, ''));
				setStatus(`Opened project ${file.name}`);
			}
		});
	});

	$('save-project').addEventListener('click', () =>
		busy('Saving the project…', async () => {
			const name = (projectName === 'New project' ? 'AutopilotBranding project' : projectName).replace(/[\\/:*?"<>|]/g, '_');
			download(`${name}.zip`, await project.toZip(), 'application/zip');
			setDirty(false);
			setStatus(`Saved ${name}.zip.  Open it again with Open…, or extract it and use it as a project folder with the PowerShell module.`);
		}),
	);

	$('validate').addEventListener('click', () => {
		const problems = validateConfiguration(project.configuration, site.definitions, project);
		showDialog('Validate', problems.length === 0 ? 'No problems found.' : problemsList(problems));
	});

	$('download-output').addEventListener('click', () =>
		busy('Preparing the output…', async () => {
			const { createZip } = await import('./intunewin');
			const files = await project.outputFiles();
			download('AutopilotBranding-output.zip', createZip(files, 6), 'application/zip');
			setStatus(`Downloaded the package content (${files.size} files)`);
		}),
	);

	$('generate').addEventListener('click', () => {
		const errors = validateConfiguration(project.configuration, site.definitions, project).filter((p) => p.Severity === 'Error');
		if (errors.length > 0) {
			showDialog('Fix these problems before generating', problemsList(errors));
			return;
		}
		void busy('Generating AutopilotBranding.intunewin…', async () => {
			const result = await project.generate();
			download('AutopilotBranding.intunewin', result.package);
			setStatus(`Generated AutopilotBranding.intunewin (${formatSize(result.package.length)}, ${result.plan.enabledTasks.length} tasks)`);
			showDialog(
				'Package generated',
				el(
					'div',
					{},
					el('p', { textContent: `AutopilotBranding.intunewin (${formatSize(result.package.length)}) contains ${result.plan.files.length} files and runs ${result.plan.enabledTasks.length} tasks.` }),
					el('p', { textContent: 'Install command: powershell.exe -noprofile -executionpolicy bypass -file .\\AutopilotBranding.ps1' }),
					el('p', { textContent: 'Uninstall command: cmd.exe /c del %ProgramData%\\Microsoft\\AutopilotBranding\\AutopilotBranding.ps1.tag' }),
					el('p', { textContent: 'Detection rule: file %ProgramData%\\Microsoft\\AutopilotBranding\\AutopilotBranding.ps1.tag exists' }),
				),
			);
		});
	});

	$('all-tasks').addEventListener('click', () => {
		for (const d of site.definitions) project.configuration.Tasks[d.Name].Enabled = true;
		setDirty();
		renderTaskList();
		renderDetails();
	});
	$('no-tasks').addEventListener('click', () => {
		for (const d of site.definitions) project.configuration.Tasks[d.Name].Enabled = false;
		setDirty();
		renderTaskList();
		renderDetails();
	});
	$('show-files').addEventListener('click', () => select('files'));

	window.addEventListener('beforeunload', (e) => {
		if (dirty) e.preventDefault();
	});
}

async function start(): Promise<void> {
	try {
		site = await loadSiteData(fetchSource);
	} catch (error) {
		$('details').replaceChildren(el('p', { className: 'placeholder', textContent: `Unable to load the builder data: ${(error as Error).message}` }));
		return;
	}
	document.title = `Autopilot Branding Builder (module v${site.manifest.ModuleVersion})`;
	$('app-version').textContent = `v${site.manifest.ModuleVersion}`;
	wireToolbar();
	setProject(Project.fromTemplate(site), 'New project');
	// Exposed for automated tests
	(window as unknown as { autopilotBranding: unknown }).autopilotBranding = { get project() { return project; }, site, CONFIG_FILE };
}

void start();
