// credentials/CyberPulseHttpHeaderAuth.credentials.ts
import type { ICredentialType, ICredentialTestRequest, INodeProperties } from 'n8n-workflow';

export class CyberPulseHeader implements ICredentialType {
  name = 'cyberPulseHeaderApi';
  displayName = 'CyberPulse Header';

  properties: INodeProperties[] = [
    {
      displayName: 'API Key',
      name: 'apiKey',
      type: 'string',
      typeOptions: { password: true },
      default: '',
      description: 'Sent as x-api-key: <API Key>',
    },
  ];

  authenticate = {
    type: 'generic' as const,
    properties: {
      headers: {
        'x-api-key': '{{$credentials.apiKey}}',
      },
    },
  };

  test: ICredentialTestRequest = {
    request: { url: 'https://httpbin.org/headers', method: 'GET' },
  };
}
