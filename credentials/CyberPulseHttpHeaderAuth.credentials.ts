// credentials/CyberPulseHttpHeaderAuth.credentials.ts
import type { ICredentialType, ICredentialTestRequest, INodeProperties } from 'n8n-workflow';

export class CyberPulseHttpHeaderAuth implements ICredentialType {
  name = 'cyberPulseHttpHeaderAuthApi';
  displayName = 'CyberPulse HTTP Header Auth';

  properties: INodeProperties[] = [
    {
      displayName: 'API Key',
      name: 'apiKey',
      type: 'string',
      typeOptions: { password: true },
      default: '',
      description: 'Sent as Authorization: Bearer <API Key>',
    },
  ];

  authenticate = {
    type: 'generic' as const,
    properties: {
      headers: {
        Authorization: 'Bearer {{$credentials.apiKey}}',
      },
    },
  };

  test: ICredentialTestRequest = {
    request: { url: 'https://httpbin.org/bearer', method: 'GET' },
  };
}
