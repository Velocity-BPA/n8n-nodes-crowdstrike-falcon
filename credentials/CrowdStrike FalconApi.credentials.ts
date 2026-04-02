import {
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class CrowdStrikeFalconApi implements ICredentialType {
	name = 'crowdStrikeFalconApi';
	displayName = 'CrowdStrike Falcon API';
	documentationUrl = 'https://falcon.crowdstrike.com/documentation/';
	properties: INodeProperties[] = [
		{
			displayName: 'Client ID',
			name: 'clientId',
			type: 'string',
			required: true,
			default: '',
			description: 'OAuth2 Client ID from CrowdStrike Falcon API',
		},
		{
			displayName: 'Client Secret',
			name: 'clientSecret',
			type: 'string',
			typeOptions: {
				password: true,
			},
			required: true,
			default: '',
			description: 'OAuth2 Client Secret from CrowdStrike Falcon API',
		},
		{
			displayName: 'API Base URL',
			name: 'apiBaseUrl',
			type: 'string',
			required: true,
			default: 'https://api.crowdstrike.com',
			description: 'Base URL for the CrowdStrike Falcon API',
		},
	];
}