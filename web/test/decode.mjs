// Decodes an .intunewin package with node:crypto (independently of the Web Crypto code that created it) and checks
// its integrity: MAC, IV, digest, sizes and setup file.

import assert from 'node:assert/strict';
import { createDecipheriv, createHash, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { unzipSync } from 'fflate';

export function tag(xml, name) {
	const match = new RegExp(`<${name}>([^<]*)</${name}>`).exec(xml);
	assert.ok(match, `Detection.xml has no ${name}`);
	return match[1];
}

/** Decodes an .intunewin: verifies the MAC and digest and returns the content zip's entries and Detection.xml. */
export function decode(path) {
	const outer = unzipSync(new Uint8Array(readFileSync(path)));
	assert.deepEqual(Object.keys(outer).sort(), ['IntuneWinPackage/Contents/IntunePackage.intunewin', 'IntuneWinPackage/Metadata/Detection.xml']);
	const xml = new TextDecoder().decode(outer['IntuneWinPackage/Metadata/Detection.xml']);
	const encrypted = Buffer.from(outer['IntuneWinPackage/Contents/IntunePackage.intunewin']);
	const key = Buffer.from(tag(xml, 'EncryptionKey'), 'base64');
	const macKey = Buffer.from(tag(xml, 'MacKey'), 'base64');
	const iv = Buffer.from(tag(xml, 'InitializationVector'), 'base64');
	assert.equal(key.length, 32);
	assert.equal(macKey.length, 32);
	assert.equal(iv.length, 16);
	const mac = encrypted.subarray(0, 32);
	assert.deepEqual(mac, Buffer.from(tag(xml, 'Mac'), 'base64'), 'MAC in the file differs from Detection.xml');
	assert.deepEqual(encrypted.subarray(32, 48), iv, 'IV in the file differs from Detection.xml');
	assert.deepEqual(createHmac('sha256', macKey).update(encrypted.subarray(32)).digest(), mac, 'HMAC does not verify');
	const decipher = createDecipheriv('aes-256-cbc', key, iv);
	const content = Buffer.concat([decipher.update(encrypted.subarray(48)), decipher.final()]);
	assert.equal(content.length, Number(tag(xml, 'UnencryptedContentSize')));
	assert.deepEqual(createHash('sha256').update(content).digest(), Buffer.from(tag(xml, 'FileDigest'), 'base64'), 'FileDigest does not match');
	assert.equal(tag(xml, 'FileDigestAlgorithm'), 'SHA256');
	assert.equal(tag(xml, 'ProfileIdentifier'), 'ProfileVersion1');
	assert.equal(tag(xml, 'SetupFile'), 'AutopilotBranding.ps1');
	return { xml, entries: unzipSync(new Uint8Array(content)) };
}
