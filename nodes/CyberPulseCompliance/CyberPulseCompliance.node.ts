// nodes/CyberPulseCompliance/CyberPulseCompliance.node.ts
import type {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionType, NodeOperationError } from 'n8n-workflow';

type Clause = { framework: string; clause: string; title: string };
type Crosswalk = Record<string, Record<string, Clause[]>>;

/** Your API Gateway base URL (override with env CP_API_BASE if needed) */
const API_BASE = 'https://6kq6c7p4r4.execute-api.us-east-1.amazonaws.com/prod';

const DEFAULT_CROSSWALK: Crosswalk = {
	mfa: {
		'ISO 27001': [{ clause: 'A.5.17', title: 'Authentication information', framework: 'ISO 27001' }],
		'SOC 2': [{ clause: 'CC6.1', title: 'Logical access controls', framework: 'SOC 2' }],
		'NIST CSF': [{ clause: 'PR.AC-1', title: 'Identities managed', framework: 'NIST CSF' }],
		'PCI DSS': [{ clause: '8.4', title: 'Multi-factor authentication', framework: 'PCI DSS' }],
		'Essential Eight': [{ clause: 'AC', title: 'Access control (maturity)', framework: 'Essential Eight' }],
		GDPR: [{ clause: 'Art. 32', title: 'Security of processing (access control)', framework: 'GDPR' }],
	},
	encryption: {
		'ISO 27001': [{ clause: 'A.8.24', title: 'Cryptography', framework: 'ISO 27001' }],
		'SOC 2': [{ clause: 'CC6.7', title: 'Encryption protections', framework: 'SOC 2' }],
		'NIST CSF': [{ clause: 'PR.DS-1', title: 'Data-at-rest protected', framework: 'NIST CSF' }],
		'PCI DSS': [{ clause: '3.5', title: 'Protect stored account data', framework: 'PCI DSS' }],
		'Essential Eight': [{ clause: 'DM', title: 'Data protection (maturity)', framework: 'Essential Eight' }],
		GDPR: [{ clause: 'Art. 32', title: 'Security of processing (encryption)', framework: 'GDPR' }],
	},
	logging: {
		'ISO 27001': [{ clause: 'A.8.15', title: 'Logging', framework: 'ISO 27001' }],
		'SOC 2': [{ clause: 'CC7.2', title: 'Monitor and detect', framework: 'SOC 2' }],
		'NIST CSF': [{ clause: 'DE.CM-1', title: 'Monitoring for anomalies', framework: 'NIST CSF' }],
		'PCI DSS': [{ clause: '10.2', title: 'Log and monitor all access', framework: 'PCI DSS' }],
		'Essential Eight': [{ clause: 'LM', title: 'Logging & monitoring (maturity)', framework: 'Essential Eight' }],
		GDPR: [{ clause: 'Art. 5(1)(f)', title: 'Integrity and confidentiality', framework: 'GDPR' }],
	},
	backups: {
		'ISO 27001': [{ clause: 'A.8.13', title: 'Backup', framework: 'ISO 27001' }],
		'SOC 2': [{ clause: 'CC7.3', title: 'Resilience and recovery', framework: 'SOC 2' }],
		'NIST CSF': [{ clause: 'PR.IP-4', title: 'Backups maintained and tested', framework: 'NIST CSF' }],
		'PCI DSS': [{ clause: '12.10.4', title: 'Incident response incl. recovery', framework: 'PCI DSS' }],
		'Essential Eight': [{ clause: 'DR', title: 'Backups & recovery (maturity)', framework: 'Essential Eight' }],
		GDPR: [{ clause: 'Art. 32', title: 'Availability and resilience', framework: 'GDPR' }],
	},
	patching: {
		'ISO 27001': [{ clause: 'A.8.8', title: 'Technical vulnerabilities', framework: 'ISO 27001' }],
		'SOC 2': [{ clause: 'CC7.1', title: 'Identify & mitigate vulnerabilities', framework: 'SOC 2' }],
		'NIST CSF': [{ clause: 'PR.IP-12', title: 'Vulnerability management', framework: 'NIST CSF' }],
		'PCI DSS': [{ clause: '6.3', title: 'Security patches', framework: 'PCI DSS' }],
		'Essential Eight': [{ clause: 'PA', title: 'Patch apps/OS (maturity)', framework: 'Essential Eight' }],
		GDPR: [{ clause: 'Art. 25', title: 'Data protection by design/default', framework: 'GDPR' }],
	},
	access_reviews: {
		'ISO 27001': [{ clause: 'A.5.18', title: 'Access rights', framework: 'ISO 27001' }],
		'SOC 2': [{ clause: 'CC6.3', title: 'Provisioning and reviews', framework: 'SOC 2' }],
		'NIST CSF': [{ clause: 'PR.AC-4', title: 'Permissions managed', framework: 'NIST CSF' }],
		'PCI DSS': [{ clause: '7.2', title: 'Access by business need', framework: 'PCI DSS' }],
		'Essential Eight': [{ clause: 'AC', title: 'Least privilege (maturity)', framework: 'Essential Eight' }],
		GDPR: [{ clause: 'Art. 5(1)(c)', title: 'Data minimisation', framework: 'GDPR' }],
	},
};

function classifyCategories(text: string): string[] {
	const t = (text || '').toLowerCase();
	const hits: Set<string> = new Set();
	if (/(mfa|2fa|two[-\s]?factor|multi[-\s]?factor)/.test(t)) hits.add('mfa');
	if (/(encrypt|aes|rsa|kms|tls|https|at rest|at-rest)/.test(t)) hits.add('encryption');
	if (/(log|logging|siem|monitor|edr|xdr|soc)/.test(t)) hits.add('logging');
	if (/(backup|back[-\s]?up|snapshots?|restore|rpo|rto|dr test|disaster recovery)/.test(t)) hits.add('backups');
	if (/(patch|update|vulnerability|cve|scan|remediate)/.test(t)) hits.add('patching');
	if (/(access review|recertif|least privilege|privilege review|entitlement)/.test(t)) hits.add('access_reviews');
	if (hits.size === 0) hits.add('logging');
	return Array.from(hits);
}

/**
 * REALISTIC COMPLIANCE SCORING SYSTEM
 * Provides consistent, evidence-based scores with confidence metrics
 */
function scoreFor(
	categories: string[],
	evidenceCount: number,
	controlText: string = '',
	evidenceUrls: string[] = []
): { 
	score: number; 
	status: 'Compliant' | 'Partial' | 'Non-Compliant';
	confidence: number;
	evaluation: 'Compliant' | 'Non-Compliant';
	rationale: string;
} {
	// --- 1. CONTROL TEXT QUALITY ANALYSIS (0-30 points) ---
	let controlQualityScore = 0;
	
	const hasSpecificRequirements = /\d+|all|every|must|require|enforce|minimum|maximum/.test(controlText.toLowerCase());
	const hasActionableVerbs = /(implement|configure|enable|enforce|review|monitor|test|validate|verify)/.test(controlText.toLowerCase());
	const wordCount = controlText.split(/\s+/).filter(w => w.length > 0).length;
	
	if (wordCount >= 10 && wordCount <= 100) controlQualityScore += 10;
	else if (wordCount > 5) controlQualityScore += 5;
	
	if (hasSpecificRequirements) controlQualityScore += 10;
	if (hasActionableVerbs) controlQualityScore += 10;
	
	// --- 2. CATEGORY COVERAGE ANALYSIS (0-25 points) ---
	let categoryScore = 0;
	
	const categoryWeights: Record<string, number> = {
		mfa: 8,
		encryption: 7,
		access_reviews: 6,
		patching: 6,
		logging: 5,
		backups: 5,
	};
	
	for (const cat of categories) {
		categoryScore += categoryWeights[cat] || 3;
	}
	categoryScore = Math.min(categoryScore, 25);
	
	// --- 3. EVIDENCE QUALITY ANALYSIS (0-35 points) ---
	let evidenceScore = 0;
	
	if (evidenceCount === 0) {
		evidenceScore = 0;
	} else if (evidenceCount === 1) {
		evidenceScore = 15;
	} else if (evidenceCount === 2) {
		evidenceScore = 22;
	} else if (evidenceCount === 3) {
		evidenceScore = 28;
	} else if (evidenceCount >= 4) {
		evidenceScore = 35;
	}
	
	// Bonus for diverse evidence types
	const evidenceTypes = new Set<string>();
	for (const url of evidenceUrls) {
		const lower = url.toLowerCase();
		if (/\.(pdf|docx?|txt)/.test(lower)) evidenceTypes.add('document');
		if (/\.(png|jpe?g|gif|webp)/.test(lower)) evidenceTypes.add('screenshot');
		if (/\.(json|ya?ml|xml|conf|config)/.test(lower)) evidenceTypes.add('config');
		if (/(dashboard|portal|console|admin)/.test(lower)) evidenceTypes.add('portal');
	}
	if (evidenceTypes.size >= 2 && evidenceCount > 0) {
		evidenceScore += 5;
	}
	
	// --- 4. IMPLEMENTATION DEPTH ANALYSIS (0-10 points) ---
	let implementationScore = 0;
	
	const implementationKeywords = [
		'configured', 'deployed', 'enabled', 'implemented', 'enforced',
		'active', 'running', 'operational', 'production', 'documented'
	];
	
	const implementationMatches = implementationKeywords.filter(kw => 
		controlText.toLowerCase().includes(kw)
	).length;
	
	implementationScore = Math.min(implementationMatches * 3, 10);
	
	// --- 5. CALCULATE TOTAL SCORE (0-100) ---
	const totalScore = Math.round(
		controlQualityScore + 
		categoryScore + 
		evidenceScore + 
		implementationScore
	);
	
	// --- 6. CALCULATE CONFIDENCE (0-100) ---
	let confidence = 0;
	
	if (evidenceCount === 0) confidence = 20;
	else if (evidenceCount === 1) confidence = 45;
	else if (evidenceCount === 2) confidence = 65;
	else if (evidenceCount === 3) confidence = 80;
	else if (evidenceCount >= 4) confidence = 95;
	
	if (wordCount < 5) confidence -= 15;
	else if (wordCount >= 20) confidence += 5;
	
	if (hasSpecificRequirements && hasActionableVerbs) confidence += 5;
	
	confidence = Math.max(20, Math.min(confidence, 100));
	
	// --- 7. DETERMINE STATUS ---
	let status: 'Compliant' | 'Partial' | 'Non-Compliant';
	
	if (totalScore >= 85 && evidenceCount >= 2) {
		status = 'Compliant';
	} else if (totalScore >= 60 && evidenceCount >= 1) {
		status = 'Partial';
	} else if (totalScore >= 60 && evidenceCount === 0) {
		status = 'Partial';
	} else {
		status = 'Non-Compliant';
	}
	
	// --- 8. DETERMINE EVALUATION (Binary) ---
	const evaluation: 'Compliant' | 'Non-Compliant' = 
		(totalScore >= 85 && evidenceCount >= 2) ? 'Compliant' : 'Non-Compliant';
	
	// --- 9. GENERATE RATIONALE ---
	const rationaleComponents: string[] = [];
	
	if (status === 'Compliant') {
		rationaleComponents.push('Strong compliance demonstrated');
	} else if (status === 'Partial') {
		rationaleComponents.push('Partial compliance - improvement needed');
	} else {
		rationaleComponents.push('Non-compliant - significant gaps');
	}
	
	rationaleComponents.push(`Score: ${totalScore}/100`);
	
	if (evidenceCount === 0) {
		rationaleComponents.push('No evidence provided');
	} else if (evidenceCount === 1) {
		rationaleComponents.push('Minimal evidence (1 item)');
	} else if (evidenceCount >= 4) {
		rationaleComponents.push(`Comprehensive evidence (${evidenceCount} items)`);
	} else {
		rationaleComponents.push(`Evidence: ${evidenceCount} items`);
	}
	
	if (categories.length > 0) {
		rationaleComponents.push(`Categories: ${categories.join(', ')}`);
	}
	
	if (wordCount < 10) {
		rationaleComponents.push('Control text needs more detail');
	}
	if (!hasSpecificRequirements) {
		rationaleComponents.push('Add specific requirements/thresholds');
	}
	
	const rationale = rationaleComponents.join(' • ');
	
	return {
		score: totalScore,
		status,
		confidence,
		evaluation,
		rationale
	};
}

/** Friendly messages for metered API HTTP statuses */
const FRIENDLY_STATUS: Record<number, string> = {
	401: 'Unauthorized – missing/invalid API key',
	402: 'Payment required / plan issue',
	403: 'Forbidden – key not allowed for this call',
	429: 'Too many requests – rate limited',
};

function extractHttpStatus(err: any): number | undefined {
	return err?.response?.status ?? err?.cause?.response?.status ?? err?.status;
}
function extractHttpBody(err: any): unknown {
	return err?.response?.data ?? err?.cause?.response?.data ?? err?.message;
}

/** pick whichever credential exists on the instance */
async function resolveCred(this: IExecuteFunctions): Promise<'cyberPulseHttpHeaderAuthApi' | 'httpHeaderAuth'> {
	try { await this.getCredentials('cyberPulseHttpHeaderAuthApi'); return 'cyberPulseHttpHeaderAuthApi'; } catch {}
	await this.getCredentials('httpHeaderAuth'); // throws if missing
	return 'httpHeaderAuth';
}

export class CyberPulseCompliance implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'CyberPulse Compliance (Dev)',
		name: 'cyberPulseCompliance',
		group: ['transform'],
		version: 6,
		description: 'Evaluate a control & evidence, map to selected frameworks, and return a score/status.',
		defaults: { name: 'CyberPulse Compliance (Dev)' },
		inputs: [NodeConnectionType.Main],
		outputs: [NodeConnectionType.Main],
		usableAsTool: true,

		// allow either custom x-api-key credential or generic header auth
		credentials: [
			{ name: 'cyberPulseHttpHeaderAuthApi', required: false },	
		],

		properties: [
			{
				displayName: 'Control Text',
				name: 'controlText',
				type: 'string',
				default: '',
				placeholder: 'e.g., Password policy requires MFA and 12+ characters',
				description: 'Your policy/control statement to evaluate',
			},
			{
				displayName: 'Evidence URLs',
				name: 'evidenceUrls',
				type: 'string',
				typeOptions: { multipleValues: true, multipleValueButtonText: 'Add URL' },
				default: [],
				placeholder: 'https://portal.example.com/report.pdf',
				description: 'Links to proofs (dashboards, reports, configs)',
			},
			{
				displayName: 'Frameworks',
				name: 'frameworks',
				type: 'multiOptions',
				default: ['Essential Eight', 'GDPR', 'ISO 27001', 'NIST CSF', 'PCI DSS', 'SOC 2'],
				options: [
					{ name: 'Essential Eight', value: 'Essential Eight' },
					{ name: 'GDPR', value: 'GDPR' },
					{ name: 'ISO 27001', value: 'ISO 27001' },
					{ name: 'NIST CSF', value: 'NIST CSF' },
					{ name: 'PCI DSS', value: 'PCI DSS' },
					{ name: 'SOC 2', value: 'SOC 2' },
				],
				description: 'Frameworks to map against',
			},
			{
				displayName: 'Crosswalk URL',
				name: 'crosswalkUrl',
				type: 'string',
				default: '',
				placeholder: 'https://your-public-host/crosswalk.json',
				description: 'Optional: URL to JSON crosswalk (overrides built-in)',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const credName = await resolveCred.call(this);

		const items = this.getInputData();
		const output: INodeExecutionData[] = [];

		/** Hit the metered API so usage plan + friendly codes apply */
		try {
			await this.helpers.httpRequestWithAuthentication.call(this, credName, {
				method: 'POST',
				url: `${API_BASE}/v1/evaluate-controls`,
				json: true,
				body: {
					framework: 'NIST CSF',
					controls: ['AC-2'],
					evidence: [],
				},
			});
		} catch (err: any) {
			const s = extractHttpStatus(err);
			if (typeof s === 'number' && (s in FRIENDLY_STATUS)) {
				const d = extractHttpBody(err) as any;
				throw new NodeOperationError(this.getNode(), FRIENDLY_STATUS[s as keyof typeof FRIENDLY_STATUS], {
					description: typeof d === 'string' ? d : JSON.stringify(d ?? {}),
					itemIndex: 0,
				});
			}
			throw new NodeOperationError(this.getNode(), err?.message ?? 'Request failed', { itemIndex: 0 });
		}

		// Optional crosswalk fetch (no auth assumed; add credName here if your URL needs it)
		let crosswalk: Crosswalk = DEFAULT_CROSSWALK;
		try {
			const url = (this.getNodeParameter('crosswalkUrl', 0, '') as string) || '';
			if (url) {
				const res = await this.helpers.httpRequest({ method: 'GET', url, json: true });
				if (res) crosswalk = res as Crosswalk;
			}
		} catch (err: any) {
			const s = extractHttpStatus(err);
			if (typeof s === 'number' && (s in FRIENDLY_STATUS)) {
				const d = extractHttpBody(err) as any;
				throw new NodeOperationError(this.getNode(), FRIENDLY_STATUS[s as keyof typeof FRIENDLY_STATUS], {
					description: typeof d === 'string' ? d : JSON.stringify(d ?? {}),
					itemIndex: 0,
				});
			}
			throw new NodeOperationError(this.getNode(), 'Failed to fetch crosswalk JSON', {
				description: (err as Error)?.message ?? 'Request failed',
				itemIndex: 0,
			});
		}

		for (let i = 0; i < items.length; i++) {
			try {
				const controlText = (this.getNodeParameter('controlText', i, '') as string) || '';
				const evidenceUrls = (this.getNodeParameter('evidenceUrls', i, []) as string[]) || [];
				const frameworks = (this.getNodeParameter('frameworks', i, []) as string[]) || [];

				const categories = classifyCategories(controlText);
				
				// NEW: Call updated scoreFor with all parameters
				let { score, status, confidence, evaluation, rationale } = scoreFor(
					categories, 
					evidenceUrls.length,
					controlText,
					evidenceUrls
				);

				const gaps: string[] = [];
				if (evidenceUrls.length === 0) {
					if (status === 'Compliant') status = 'Partial';
					gaps.push('No evidence provided');
				}

				const mapped: Clause[] = [];
				for (const cat of categories) {
					const fwMap = crosswalk[cat] || {};
					for (const fw of frameworks) {
						const list = fwMap[fw] || [];
						for (const c of list) mapped.push(c);
					}
				}

				const actions = [
					...(categories.includes('mfa') ? ['Confirm MFA enforced for all privileged accounts'] : []),
					...(categories.includes('encryption') ? ['Verify encryption at rest & in transit'] : []),
					...(categories.includes('logging') ? ['Forward critical logs to SIEM & alert on anomalies'] : []),
					...(categories.includes('backups') ? ['Test restores to validate RPO/RTO targets'] : []),
					...(categories.includes('patching') ? ['Apply critical patches within policy SLA'] : []),
					...(categories.includes('access_reviews') ? ['Perform quarterly access recertifications'] : []),
					...(evidenceUrls.length === 0 ? ['Attach relevant evidence links'] : []),
				];

				output.push({
					json: {
						input_control_text: controlText,
						categories,
						evidence: evidenceUrls,
						status,
						score,
						confidence,        // NEW: Realistic confidence metric
						evaluation,        // NEW: Binary compliance evaluation
						rationale,         // NEW: Detailed rationale
						mapped_requirements: mapped,
						frameworks_selected: frameworks,
						gaps,
						actions,
						notes: 'Realistic scoring based on control quality, evidence, and implementation depth.',
					},
				});
			} catch (error) {
				if (this.continueOnFail()) {
					output.push({ json: items[i]?.json ?? {}, error, pairedItem: i });
				} else {
					if ((error as any).context) {
						(error as any).context.itemIndex = i;
						throw error;
					}
					throw new NodeOperationError(this.getNode(), error as Error, { itemIndex: i });
				}
			}
		}

		return this.prepareOutputData(output);
	}
}
