import type { ICredentialType, ICredentialTestRequest, INodeProperties } from 'n8n-workflow';

export class HttpHeaderAuth implements ICredentialType {
  name = 'httpHeaderAuthApi';
  displayName = 'CyberPulse HTTP Header Auth'; // <— make it unique

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

  authenticate = {
    type: 'generic' as const,
    properties: {
      headers: {
        Authorization: '={{$credentials.headerValue}}',
      },
    },
  };

  test: ICredentialTestRequest = {
    request: { url: 'https://httpbin.org/anything', method: 'GET' },
  };
}
