// Types shared by the web builder.  The task definitions are exported from the PowerShell module at build time
// (Get-ABTaskDefinition, see scripts/Export-WebData.ps1), so the web builder always matches the module it packages.

export type ParameterKind = 'String' | 'StringArray' | 'Boolean' | 'Switch' | 'Integer';
export type AssetKind = 'File' | 'Folder' | null;
export type ParameterValue = string | string[] | boolean | number | null;

export interface ParameterDefinition {
	Name: string;
	Kind: ParameterKind;
	TypeName: string;
	Mandatory: boolean;
	ValidateSet: string[] | null;
	DefaultValue: ParameterValue;
	AssetKind: AssetKind;
	HelpText: string;
}

export interface TaskDefinition {
	Name: string;
	Order: number;
	FileName: string;
	Synopsis: string;
	Description: string;
	Parameters: ParameterDefinition[];
}

export interface TaskEntry {
	Enabled: boolean;
	Parameters: Record<string, ParameterValue>;
}

export interface Configuration {
	Version: number;
	Description?: string;
	Tasks: Record<string, TaskEntry>;
	[key: string]: unknown;
}

/** Describes the data files published with the site (written by scripts/Export-WebData.ps1). */
export interface SiteManifest {
	ModuleVersion: string;
	/** Paths of the module files, relative to data/module (the module minus its Template folder). */
	ModuleFiles: string[];
	/** Paths of the default project template's files, relative to data/template (e.g. Assets/Autopilot.jpg). */
	TemplateFiles: string[];
	/** Path of the runner script, relative to data/module. */
	Runner: string;
}

export interface Problem {
	Severity: 'Error' | 'Warning';
	Task: string;
	Parameter: string | null;
	Message: string;
}

/** Reads the published data files: in the browser with fetch, in Node from the file system. */
export interface DataSource {
	readText(path: string): Promise<string>;
	readBytes(path: string): Promise<Uint8Array>;
}
