// Creates an Intune Win32 app package (.intunewin) in the browser (or in Node), using fflate for zip and the Web
// Crypto API for encryption.
//
// Format (the same as the Microsoft Win32 Content Prep Tool and SvRooij.ContentPrep produce; Microsoft doesn't
// document it, so CI checks packages from this code against one made by SvRooij.ContentPrep):
//   outer zip (stored, not compressed)
//     IntuneWinPackage/Contents/IntunePackage.intunewin   the encrypted content:
//         HMAC-SHA256 (32 bytes) | IV (16 bytes) | AES-256-CBC (PKCS#7) ciphertext of the content zip
//         The HMAC (keyed with a separate random MAC key) covers IV | ciphertext.
//     IntuneWinPackage/Metadata/Detection.xml             keys, IV, MAC, the SHA-256 of the content zip, sizes, setup file
//   content zip: the source folder (setup file at the root)

import { zipSync, type Zippable } from 'fflate';

export interface IntuneWinOptions {
	/** The setup file (relative path inside the content), e.g. AutopilotBranding.ps1. */
	setupFile: string;
	/** Written to Detection.xml as ToolVersion. */
	toolVersion?: string;
	/** Compression level for the content zip (0-9). */
	level?: 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;
}

export interface IntuneWinResult {
	/** The .intunewin file. */
	package: Uint8Array;
	/** The unencrypted content zip (handy for inspecting what was packaged). */
	contentZip: Uint8Array;
	detectionXml: string;
}

function getCrypto(): Crypto {
	const c = (globalThis as { crypto?: Crypto }).crypto;
	if (!c || !c.subtle) throw new Error('The Web Crypto API is not available (a secure context, https or localhost, is required).');
	return c;
}

export function toBase64(bytes: Uint8Array): string {
	let binary = '';
	const chunk = 0x8000;
	for (let i = 0; i < bytes.length; i += chunk) {
		binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
	}
	return btoa(binary);
}

/** fflate returns Uint8Array<ArrayBufferLike>; Web Crypto wants an ArrayBuffer-backed view (it always is here). */
function bytes(data: Uint8Array): Uint8Array<ArrayBuffer> {
	return data as Uint8Array<ArrayBuffer>;
}

function escapeXml(text: string): string {
	return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** Builds a zip from a map of relative paths (forward slashes) to file contents. */
export function createZip(files: Map<string, Uint8Array>, level: number): Uint8Array {
	const tree: Zippable = {};
	for (const [path, data] of files) {
		tree[path.replace(/\\/g, '/')] = [data, { level: level as 0 }];
	}
	return zipSync(tree);
}

/** Creates the .intunewin package for the given content files. */
export async function createIntuneWin(files: Map<string, Uint8Array>, options: IntuneWinOptions): Promise<IntuneWinResult> {
	const crypto = getCrypto();
	const setupFile = options.setupFile.replace(/\\/g, '/');
	if (![...files.keys()].some((path) => path.replace(/\\/g, '/').toLowerCase() === setupFile.toLowerCase())) {
		throw new Error(`The setup file ${options.setupFile} is not in the content.`);
	}

	const contentZip = createZip(files, options.level ?? 6);

	const encryptionKey = crypto.getRandomValues(new Uint8Array(32));
	const macKey = crypto.getRandomValues(new Uint8Array(32));
	const iv = crypto.getRandomValues(new Uint8Array(16));

	const aesKey = await crypto.subtle.importKey('raw', encryptionKey, { name: 'AES-CBC' }, false, ['encrypt']);
	const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, bytes(contentZip)));

	const ivAndCiphertext = new Uint8Array(iv.length + ciphertext.length);
	ivAndCiphertext.set(iv, 0);
	ivAndCiphertext.set(ciphertext, iv.length);
	const hmacKey = await crypto.subtle.importKey('raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const mac = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, ivAndCiphertext));

	const encrypted = new Uint8Array(mac.length + ivAndCiphertext.length);
	encrypted.set(mac, 0);
	encrypted.set(ivAndCiphertext, mac.length);

	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes(contentZip)));
	const setupName = setupFile.split('/').pop() as string;

	const detectionXml =
		'<?xml version="1.0" encoding="utf-8"?>\r\n' +
		`<ApplicationInfo xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ToolVersion="${escapeXml(options.toolVersion ?? '1.8.6.0')}">\r\n` +
		`  <Name>${escapeXml(setupName)}</Name>\r\n` +
		`  <UnencryptedContentSize>${contentZip.length}</UnencryptedContentSize>\r\n` +
		'  <FileName>IntunePackage.intunewin</FileName>\r\n' +
		`  <SetupFile>${escapeXml(setupName)}</SetupFile>\r\n` +
		'  <EncryptionInfo>\r\n' +
		`    <EncryptionKey>${toBase64(encryptionKey)}</EncryptionKey>\r\n` +
		`    <MacKey>${toBase64(macKey)}</MacKey>\r\n` +
		`    <InitializationVector>${toBase64(iv)}</InitializationVector>\r\n` +
		`    <Mac>${toBase64(mac)}</Mac>\r\n` +
		'    <ProfileIdentifier>ProfileVersion1</ProfileIdentifier>\r\n' +
		`    <FileDigest>${toBase64(digest)}</FileDigest>\r\n` +
		'    <FileDigestAlgorithm>SHA256</FileDigestAlgorithm>\r\n' +
		'  </EncryptionInfo>\r\n' +
		'</ApplicationInfo>';

	const outer = new Map<string, Uint8Array>([
		['IntuneWinPackage/Contents/IntunePackage.intunewin', encrypted],
		['IntuneWinPackage/Metadata/Detection.xml', new TextEncoder().encode(detectionXml)],
	]);
	return { package: createZip(outer, 0), contentZip, detectionXml };
}
