// credentials/CyberPulseHttpHeaderAuth.credentials.ts
import type { ICredentialType, ICredentialTestRequest, INodeProperties } from 'n8n-workflow';

export class CyberPulseHttpHeaderAuth implements ICredentialType {
  name = 'cyberPulseHttpHeaderAuthApi';
  displayName = 'CyberPulse HTTP Header Auth';
  icon = 'file:../nodes/CyberPulseCompliance/complianceAgent.svg' as const;
  documentationUrl = 'https://github.com/gitadta/cyberpulse-node-dev';

  properties: INodeProperties[] = [
    {
      displayName: 'API Key',
      name: 'apiKey',
      type: 'string',
      typeOptions: { password: true },
      default: '',
      description: 'Sent as x-api-key header',
    },
  ];
  
  authenticate = {
    type: 'generic' as const,
    properties: {
      headers: {
        'x-api-key': '={{$credentials.apiKey}}',  // ✅ FIXED: Added = sign
      },
    },
  };
  
  test: ICredentialTestRequest = {
    request: {
      url: 'https://www.cyberpulsesolutions.com/api/n8n-credential-test',
      method: 'GET'
    },
  };
}
