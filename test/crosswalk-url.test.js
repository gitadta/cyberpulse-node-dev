const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const ts = require('typescript');
const vm = require('node:vm');

function loadComplianceNode() {
	const source = fs.readFileSync(
		path.join(__dirname, '..', 'nodes', 'CyberPulseCompliance', 'CyberPulseCompliance.node.ts'),
		'utf8',
	);
	const compiled = ts.transpileModule(source, {
		compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
	}).outputText;
	const module = { exports: {} };
	const runModule = vm.runInThisContext(`(function (require, module, exports) {${compiled}\n})`);
	runModule(
		(request) => {
			if (request === 'n8n-workflow') return { NodeOperationError: class NodeOperationError extends Error {} };
			return require(request);
		},
		module,
		module.exports,
	);
	return module.exports.CyberPulseCompliance;
}

async function executeWithParameters(parameters) {
	const CyberPulseCompliance = loadComplianceNode();
	let crosswalkRequestCount = 0;
	const context = {
		getCredentials: async () => ({}),
		getInputData: () => [{ json: {} }],
		getNodeParameter: (name, _index, fallback) => parameters[name] ?? fallback,
		helpers: {
			httpRequestWithAuthentication: async () => ({}),
			httpRequest: async () => {
				crosswalkRequestCount += 1;
				throw new Error('A remote crosswalk request must not occur');
			},
		},
		prepareOutputData: (items) => [items],
		continueOnFail: () => false,
		getNode: () => ({}),
	};
	const output = await CyberPulseCompliance.prototype.execute.call(context);
	return { output, crosswalkRequestCount };
}

test('ignores a supplied crosswalk URL and retains bundled framework mapping', async () => {
	const { output, crosswalkRequestCount } = await executeWithParameters({
		crosswalkUrl: 'https://example.invalid/crosswalk.json',
		controlText: 'MFA must be enforced for all privileged accounts.',
		evidenceUrls: [],
		frameworks: ['ISO 27001'],
	});

	assert.equal(crosswalkRequestCount, 0);
	assert.deepEqual(output[0][0].json.mapped_requirements, [
		{ clause: 'A.5.17', title: 'Authentication information', framework: 'ISO 27001' },
	]);
});

test('processes a normal bundled crosswalk evaluation without a remote URL', async () => {
	const { output, crosswalkRequestCount } = await executeWithParameters({
		controlText: 'MFA must be enforced for all privileged accounts.',
		evidenceUrls: [],
		frameworks: ['ISO 27001'],
	});

	assert.equal(crosswalkRequestCount, 0);
	assert.deepEqual(output[0][0].json.mapped_requirements, [
		{ clause: 'A.5.17', title: 'Authentication information', framework: 'ISO 27001' },
	]);
});
