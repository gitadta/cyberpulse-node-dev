// credentials/CyberPulseHttpHeaderAuth.credentials.ts
import type { ICredentialType, ICredentialTestRequest, INodeProperties } from 'n8n-workflow';

export class CyberPulseHttpHeaderAuth implements ICredentialType {
  // keep the "name" property with -Api (that’s what the linter wanted)
  name = 'cyberPulseHttpHeaderAuthApi';
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
