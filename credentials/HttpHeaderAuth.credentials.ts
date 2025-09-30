import type { ICredentialType, ICredentialTestRequest, INodeProperties } from 'n8n-workflow';

export class HttpHeaderAuth implements ICredentialType {
	name = 'httpHeaderAuth';
	displayName = 'HTTP Header Auth';

	properties: INodeProperties[] = [
		{
			displayName: 'API Key',
			name: 'headerValue',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description: 'Sent as Authorization header',
		},
	];

	// attach header to every request from nodes using this credential
	authenticate = {
		type: 'generic' as const,
		properties: {
			headers: {
				Authorization: '={{$credentials.headerValue}}',
			},
		},
	};

	// simple test request so the green “Test” works
	test: ICredentialTestRequest = {
		request: {
			url: 'https://httpbin.org/anything',
			method: 'GET',
		},
	};
}
