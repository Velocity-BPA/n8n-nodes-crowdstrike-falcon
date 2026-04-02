/**
 * Copyright (c) 2026 Velocity BPA
 * Licensed under the Business Source License 1.1
 */

import { IExecuteFunctions, INodeExecutionData } from 'n8n-workflow';
import { CrowdStrikeFalcon } from '../nodes/CrowdStrike Falcon/CrowdStrike Falcon.node';

// Mock n8n-workflow
jest.mock('n8n-workflow', () => ({
  ...jest.requireActual('n8n-workflow'),
  NodeApiError: class NodeApiError extends Error {
    constructor(node: any, error: any) { super(error.message || 'API Error'); }
  },
  NodeOperationError: class NodeOperationError extends Error {
    constructor(node: any, message: string) { super(message); }
  },
}));

describe('CrowdStrikeFalcon Node', () => {
  let node: CrowdStrikeFalcon;

  beforeAll(() => {
    node = new CrowdStrikeFalcon();
  });

  describe('Node Definition', () => {
    it('should have correct basic properties', () => {
      expect(node.description.displayName).toBe('CrowdStrike Falcon');
      expect(node.description.name).toBe('crowdstrikefalcon');
      expect(node.description.version).toBe(1);
      expect(node.description.inputs).toContain('main');
      expect(node.description.outputs).toContain('main');
    });

    it('should define 7 resources', () => {
      const resourceProp = node.description.properties.find(
        (p: any) => p.name === 'resource'
      );
      expect(resourceProp).toBeDefined();
      expect(resourceProp!.type).toBe('options');
      expect(resourceProp!.options).toHaveLength(7);
    });

    it('should have operation dropdowns for each resource', () => {
      const operations = node.description.properties.filter(
        (p: any) => p.name === 'operation'
      );
      expect(operations.length).toBe(7);
    });

    it('should require credentials', () => {
      expect(node.description.credentials).toBeDefined();
      expect(node.description.credentials!.length).toBeGreaterThan(0);
      expect(node.description.credentials![0].required).toBe(true);
    });

    it('should have parameters with proper displayOptions', () => {
      const params = node.description.properties.filter(
        (p: any) => p.displayOptions?.show?.resource
      );
      for (const param of params) {
        expect(param.displayOptions.show.resource).toBeDefined();
        expect(Array.isArray(param.displayOptions.show.resource)).toBe(true);
      }
    });
  });

  // Resource-specific tests
describe('Detections Resource', () => {
  let mockExecuteFunctions: any;

  beforeEach(() => {
    mockExecuteFunctions = {
      getNodeParameter: jest.fn(),
      getCredentials: jest.fn().mockResolvedValue({
        accessToken: 'test-token',
        baseUrl: 'https://api.crowdstrike.com',
      }),
      getInputData: jest.fn().mockReturnValue([{ json: {} }]),
      getNode: jest.fn().mockReturnValue({ name: 'Test Node' }),
      continueOnFail: jest.fn().mockReturnValue(false),
      helpers: {
        httpRequest: jest.fn(),
        requestWithAuthentication: jest.fn(),
      },
    };
  });

  describe('queryDetections operation', () => {
    it('should query detections successfully', async () => {
      mockExecuteFunctions.getNodeParameter
        .mockReturnValueOnce('queryDetections')
        .mockReturnValueOnce(100)
        .mockReturnValueOnce(0)
        .mockReturnValueOnce('')
        .mockReturnValueOnce('');

      const mockResponse = {
        resources: ['detection1', 'detection2'],
        meta: { query_time: 0.123 },
      };

      mockExecuteFunctions.helpers.httpRequest.mockResolvedValue(mockResponse);

      const result = await executeDetectionsOperations.call(mockExecuteFunctions, [{ json: {} }]);

      expect(result).toEqual([
        {
          json: mockResponse,
          pairedItem: { item: 0 },
        },
      ]);
    });

    it('should handle query detections error', async () => {
      mockExecuteFunctions.getNodeParameter
        .mockReturnValueOnce('queryDetections')
        .mockReturnValueOnce(100)
        .mockReturnValueOnce(0)
        .mockReturnValueOnce('')
        .mockReturnValueOnce('');

      mockExecuteFunctions.helpers.httpRequest.mockRejectedValue(new Error('API Error'));
      mockExecuteFunctions.continueOnFail.mockReturnValue(true);

      const result = await executeDetectionsOperations.call(mockExecuteFunctions, [{ json: {} }]);

      expect(result).toEqual([
        {
          json: { error: 'API Error' },
          pairedItem: { item: 0 },
        },
      ]);
    });
  });

  describe('getDetections operation', () => {
    it('should get detections successfully', async () => {
      mockExecuteFunctions.getNodeParameter
        .mockReturnValueOnce('getDetections')
        .mockReturnValueOnce('id1,id2,id3');

      const mockResponse = {
        resources: [
          { id: 'id1', status: 'new' },
          { id: 'id2', status: 'in_progress' },
        ],
      };

      mockExecuteFunctions.helpers.httpRequest.mockResolvedValue(mockResponse);

      const result = await executeDetectionsOperations.call(mockExecuteFunctions, [{ json: {} }]);

      expect(result).toEqual([
        {
          json: mockResponse,
          pairedItem: { item: 0 },
        },
      ]);
    });

    it('should handle get detections error', async () => {
      mockExecuteFunctions.getNodeParameter
        .mockReturnValueOnce('getDetections')
        .mockReturnValueOnce('id1,id2');

      mockExecuteFunctions.helpers.httpRequest.mockRejectedValue(new Error('Not found'));
      mockExecuteFunctions.continueOnFail.mockReturnValue(true);

      const result = await executeDetectionsOperations.call(mockExecuteFunctions, [{ json: {} }]);

      expect(result).toEqual([
        {
          json: { error: 'Not found' },
          pairedItem: { item: 0 },
        },
      ]);
    });
  });

  describe('updateDetections operation', () => {
    it('should update detections successfully', async () => {
      mockExecuteFunctions.getNodeParameter
        .mockReturnValueOnce('updateDetections')
        .mockReturnValueOnce('id1,id2')
        .mockReturnValueOnce('true_positive')
        .mockReturnValueOnce('user-uuid-123');

      const mockResponse = {
        resources: [
          { id: 'id1', status: 'true_positive' },
          { id: 'id2', status: 'true_positive' },
        ],
      };

      mockExecuteFunctions.helpers.httpRequest.mockResolvedValue(mockResponse);

      const result = await executeDetectionsOperations.call(mockExecuteFunctions, [{ json: {} }]);

      expect(result).toEqual([
        {
          json: mockResponse,
          pairedItem: { item: 0 },
        },
      ]);
    });

    it('should handle update detections error', async () => {
      mockExecuteFunctions.getNodeParameter
        .mockReturnValueOnce('updateDetections')
        .mockReturnValueOnce('id1')
        .mockReturnValueOnce('false_positive')
        .mockReturnValueOnce('');

      mockExecuteFunctions.helpers.httpRequest.mockRejectedValue(new Error('Unauthorized'));
      mockExecuteFunctions.continueOnFail.mockReturnValue(false);

      await expect(
        executeDetectionsOperations.call(mockExecuteFunctions, [{ json: {} }])
      ).rejects.toThrow('Unauthorized');
    });
  });
});

describe('Incidents Resource', () => {
  let mockExecuteFunctions: any;

  beforeEach(() => {
    mockExecuteFunctions = {
      getNodeParameter: jest.fn(),
      getCredentials: jest.fn().mockResolvedValue({
        accessToken: 'test-token',
        baseUrl: 'https://api.crowdstrike.com'
      }),
      getInputData: jest.fn().mockReturnValue([{ json: {} }]),
      getNode: jest.fn().mockReturnValue({ name: 'Test Node' }),
      continueOnFail: jest.fn().mockReturnValue(false),
      helpers: {
        httpRequest: jest.fn(),
        requestWithAuthentication: jest.fn()
      },
    };
  });

  describe('queryIncidents', () => {
    it('should query incidents successfully', async () => {
      mockExecuteFunctions.getNodeParameter
        .mockReturnValueOnce('queryIncidents')
        .mockReturnValueOnce(100)
        .mockReturnValueOnce(0)
        .mockReturnValueOnce('created_timestamp.desc')
        .mockReturnValueOnce('status:\'open\'');

      mockExecuteFunctions.helpers.httpRequest.mockResolvedValue({
        resources: ['inc:12345', 'inc:67890']
      });

      const result = await executeIncidentsOperations.call(
        mockExecuteFunctions,
        [{ json: {} }]
      );

      expect(result).toHaveLength(1);
      expect(result[0].json.resources).toContain('inc:12345');
      expect(mockExecuteFunctions.helpers.httpRequest).toHaveBeenCalledWith(
        expect.objectContaining({
          method: 'GET',
          url: expect.stringContaining('/incidents/queries/incidents/v1')
        })
      );
    });

    it('should handle query incidents error', async () => {
      mockExecuteFunctions.getNodeParameter.mockReturnValueOnce('queryIncidents');
      mockExecuteFunctions.helpers.httpRequest.mockRejectedValue(new Error('API Error'));
      mockExecuteFunctions.continueOnFail.mockReturnValue(true);

      const result = await executeIncidentsOperations.call(
        mockExecuteFunctions,
        [{ json: {} }]
      );

      expect(result[0].json.error).toBe('API Error');
    });
  });

  describe('getIncidents', () => {
    it('should get incident details successfully', async () => {
      mockExecuteFunctions.getNodeParameter
        .mockReturnValueOnce('getIncidents')
        .mockReturnValueOnce('inc:12345,inc:67890');

      mockExecuteFunctions.helpers.httpRequest.mockResolvedValue({
        resources: [
          { id: 'inc:12345', status: 'open', severity: 'high' },
          { id: 'inc:67890', status: 'closed', severity: 'medium' }
        ]
      });

      const result = await executeIncidentsOperations.call(
        mockExecuteFunctions,
        [{ json: {} }]
      );

      expect(result).toHaveLength(1);
      expect(result[0].json.resources).toHaveLength(2);
      expect(mockExecuteFunctions.helpers.httpRequest).toHaveBeenCalledWith(
        expect.objectContaining({
          method: 'GET',
          url: expect.stringContaining('/incidents/entities/incidents/GET/v1')
        })
      );
    });
  });

  describe('updateIncidents', () => {
    it('should update incidents successfully', async () => {
      mockExecuteFunctions.getNodeParameter
        .mockReturnValueOnce('updateIncidents')
        .mockReturnValueOnce('inc:12345')
        .mockReturnValueOnce('in_progress')
        .mockReturnValueOnce('high');

      mockExecuteFunctions.helpers.httpRequest.mockResolvedValue({
        resources: [{ id: 'inc:12345', status: 'in_progress', severity: 'high' }]
      });

      const result = await executeIncidentsOperations.call(
        mockExecuteFunctions,
        [{ json: {} }]
      );

      expect(result).toHaveLength(1);
      expect(mockExecuteFunctions.helpers.httpRequest).toHaveBeenCalledWith(
        expect.objectContaining({
          method: 'PATCH',
          url: expect.stringContaining('/incidents/entities/incidents/v1')
        })
      );
    });
  });

  describe('performIncidentAction', () => {
    it('should perform incident action successfully', async () => {
      mockExecuteFunctions.getNodeParameter
        .mockReturnValueOnce('performIncidentAction')
        .mockReturnValueOnce('inc:12345')
        .mockReturnValueOnce('{"add_tag": "priority", "comment": "Investigation started"}');

      mockExecuteFunctions.helpers.httpRequest.mockResolvedValue({
        resources: [{ id: 'inc:12345', action_status: 'completed' }]
      });

      const result = await executeIncidentsOperations.call(
        mockExecuteFunctions,
        [{ json: {} }]
      );

      expect(result).toHaveLength(1);
      expect(mockExecuteFunctions.helpers.httpRequest).toHaveBeenCalledWith(
        expect.objectContaining({
          method: 'POST',
          url: expect.stringContaining('/incidents/entities/incident-actions/v1')
        })
      );
    });

    it('should handle invalid JSON in action parameters', async () => {
      mockExecuteFunctions.getNodeParameter
        .mockReturnValueOnce('performIncidentAction')
        .mockReturnValueOnce('inc:12345')
        .mockReturnValueOnce('invalid json');

      await expect(executeIncidentsOperations.call(
        mockExecuteFunctions,
        [{ json: {} }]
      )).rejects.toThrow('Invalid JSON in action parameters');
    });
  });
});

describe('Hosts Resource', () => {
  let mockExecuteFunctions: any;

  beforeEach(() => {
    mockExecuteFunctions = {
      getNodeParameter: jest.fn(),
      getCredentials: jest.fn().mockResolvedValue({
        access_token: 'test-token',
        baseUrl: 'https://api.crowdstrike.com'
      }),
      getInputData: jest.fn().mockReturnValue([{ json: {} }]),
      getNode: jest.fn().mockReturnValue({ name: 'Test Node' }),
      continueOnFail: jest.fn().mockReturnValue(false),
      helpers: {
        httpRequest: jest.fn(),
        requestWithAuthentication: jest.fn(),
      },
    };
  });

  it('should query devices successfully', async () => {
    mockExecuteFunctions.getNodeParameter
      .mockReturnValueOnce('queryDevices')
      .mockReturnValueOnce(100)
      .mockReturnValueOnce(0)
      .mockReturnValueOnce('hostname.asc')
      .mockReturnValueOnce('platform_name:"Windows"');

    mockExecuteFunctions.helpers.httpRequest.mockResolvedValue({
      resources: ['device1', 'device2']
    });

    const result = await executeHostsOperations.call(mockExecuteFunctions, [{ json: {} }]);

    expect(result).toHaveLength(1);
    expect(result[0].json.resources).toEqual(['device1', 'device2']);
    expect(mockExecuteFunctions.helpers.httpRequest).toHaveBeenCalledWith({
      method: 'GET',
      url: expect.stringContaining('/devices/queries/devices/v1'),
      headers: expect.objectContaining({
        'Authorization': 'Bearer test-token'
      }),
      json: true,
    });
  });

  it('should get device details successfully', async () => {
    mockExecuteFunctions.getNodeParameter
      .mockReturnValueOnce('getDevices')
      .mockReturnValueOnce('device1,device2');

    mockExecuteFunctions.helpers.httpRequest.mockResolvedValue({
      resources: [{ device_id: 'device1' }, { device_id: 'device2' }]
    });

    const result = await executeHostsOperations.call(mockExecuteFunctions, [{ json: {} }]);

    expect(result).toHaveLength(1);
    expect(result[0].json.resources).toHaveLength(2);
  });

  it('should perform device action successfully', async () => {
    mockExecuteFunctions.getNodeParameter
      .mockReturnValueOnce('performDeviceAction')
      .mockReturnValueOnce('device1,device2')
      .mockReturnValueOnce('contain');

    mockExecuteFunctions.helpers.httpRequest.mockResolvedValue({
      resources: [{ id: 'action1' }]
    });

    const result = await executeHostsOperations.call(mockExecuteFunctions, [{ json: {} }]);

    expect(result).toHaveLength(1);
    expect(mockExecuteFunctions.helpers.httpRequest).toHaveBeenCalledWith({
      method: 'POST',
      url: expect.stringContaining('/devices/entities/devices-actions/v2'),
      headers: expect.objectContaining({
        'Authorization': 'Bearer test-token'
      }),
      body: {
        ids: ['device1', 'device2']
      },
      json: true,
    });
  });

  it('should query devices with scroll successfully', async () => {
    mockExecuteFunctions.getNodeParameter
      .mockReturnValueOnce('queryDevicesScroll')
      .mockReturnValueOnce(1000)
      .mockReturnValueOnce(0)
      .mockReturnValueOnce('platform_name:"Linux"');

    mockExecuteFunctions.helpers.httpRequest.mockResolvedValue({
      resources: ['device3', 'device4']
    });

    const result = await executeHostsOperations.call(mockExecuteFunctions, [{ json: {} }]);

    expect(result).toHaveLength(1);
    expect(result[0].json.resources).toEqual(['device3', 'device4']);
  });

  it('should handle errors gracefully', async () => {
    mockExecuteFunctions.getNodeParameter.mockReturnValueOnce('queryDevices');
    mockExecuteFunctions.helpers.httpRequest.mockRejectedValue(new Error('API Error'));
    mockExecuteFunctions.continueOnFail.mockReturnValue(true);

    const result = await executeHostsOperations.call(mockExecuteFunctions, [{ json: {} }]);

    expect(result).toHaveLength(1);
    expect(result[0].json.error).toBe('API Error');
  });

  it('should throw error for unknown operation', async () => {
    mockExecuteFunctions.getNodeParameter.mockReturnValueOnce('unknownOperation');

    await expect(
      executeHostsOperations.call(mockExecuteFunctions, [{ json: {} }])
    ).rejects.toThrow('Unknown operation: unknownOperation');
  });
});

describe('IOCs Resource', () => {
  let mockExecuteFunctions: any;

  beforeEach(() => {
    mockExecuteFunctions = {
      getNodeParameter: jest.fn(),
      getCredentials: jest.fn().mockResolvedValue({ 
        apiKey: 'test-key', 
        baseUrl: 'https://api.crowdstrike.com',
        accessToken: 'test-token'
      }),
      getInputData: jest.fn().mockReturnValue([{ json: {} }]),
      getNode: jest.fn().mockReturnValue({ name: 'Test Node' }),
      continueOnFail: jest.fn().mockReturnValue(false),
      helpers: { httpRequest: jest.fn(), requestWithAuthentication: jest.fn() },
    };
  });

  it('should query IOCs successfully', async () => {
    mockExecuteFunctions.getNodeParameter
      .mockReturnValueOnce('queryIOCs')
      .mockReturnValueOnce(100)
      .mockReturnValueOnce(0)
      .mockReturnValueOnce('created_on')
      .mockReturnValueOnce('type:"domain"')
      .mockReturnValueOnce('domain,ip');

    mockExecuteFunctions.helpers.httpRequest.mockResolvedValue({
      meta: { pagination: { limit: 100, offset: 0, total: 50 } },
      resources: ['ioc-id-1', 'ioc-id-2']
    });

    const result = await executeIOCsOperations.call(mockExecuteFunctions, [{ json: {} }]);

    expect(result).toHaveLength(1);
    expect(result[0].json.resources).toEqual(['ioc-id-1', 'ioc-id-2']);
  });

  it('should get IOCs successfully', async () => {
    mockExecuteFunctions.getNodeParameter
      .mockReturnValueOnce('getIOCs')
      .mockReturnValueOnce('ioc-id-1,ioc-id-2');

    mockExecuteFunctions.helpers.httpRequest.mockResolvedValue({
      resources: [
        { id: 'ioc-id-1', type: 'domain', value: 'malicious.com' },
        { id: 'ioc-id-2', type: 'ip', value: '192.168.1.1' }
      ]
    });

    const result = await executeIOCsOperations.call(mockExecuteFunctions, [{ json: {} }]);

    expect(result).toHaveLength(1);
    expect(result[0].json.resources).toHaveLength(2);
  });

  it('should create IOCs successfully', async () => {
    const indicators = [
      { type: 'domain', value: 'test.com', policy: 'detect' }
    ];

    mockExecuteFunctions.getNodeParameter
      .mockReturnValueOnce('createIOCs')
      .mockReturnValueOnce(JSON.stringify(indicators));

    mockExecuteFunctions.helpers.httpRequest.mockResolvedValue({
      resources: [{ id: 'new-ioc-id', type: 'domain', value: 'test.com' }]
    });

    const result = await executeIOCsOperations.call(mockExecuteFunctions, [{ json: {} }]);

    expect(result).toHaveLength(1);
    expect(result[0].json.resources).toHaveLength(1);
  });

  it('should update IOCs successfully', async () => {
    const indicators = [
      { id: 'ioc-id-1', policy: 'prevent' }
    ];

    mockExecuteFunctions.getNodeParameter
      .mockReturnValueOnce('updateIOCs')
      .mockReturnValueOnce(JSON.stringify(indicators));

    mockExecuteFunctions.helpers.httpRequest.mockResolvedValue({
      resources: [{ id: 'ioc-id-1', type: 'domain', value: 'test.com', policy: 'prevent' }]
    });

    const result = await executeIOCsOperations.call(mockExecuteFunctions, [{ json: {} }]);

    expect(result).toHaveLength(1);
    expect(result[0].json.resources).toHaveLength(1);
  });

  it('should delete IOCs successfully', async () => {
    mockExecuteFunctions.getNodeParameter
      .mockReturnValueOnce('deleteIOCs')
      .mockReturnValueOnce('ioc-id-1,ioc-id-2');

    mockExecuteFunctions.helpers.httpRequest.mockResolvedValue({
      resources: ['ioc-id-1', 'ioc-id-2']
    });

    const result = await executeIOCsOperations.call(mockExecuteFunctions, [{ json: {} }]);

    expect(result).toHaveLength(1);
    expect(result[0].json.resources).toEqual(['ioc-id-1', 'ioc-id-2']);
  });

  it('should handle errors when continue on fail is enabled', async () => {
    mockExecuteFunctions.getNodeParameter.mockReturnValueOnce('queryIOCs');
    mockExecuteFunctions.continueOnFail.mockReturnValue(true);
    mockExecuteFunctions.helpers.httpRequest.mockRejectedValue(new Error('API Error'));

    const result = await executeIOCsOperations.call(mockExecuteFunctions, [{ json: {} }]);

    expect(result).toHaveLength(1);
    expect(result[0].json.error).toBe('API Error');
  });
});

describe('Vulnerabilities Resource', () => {
  let mockExecuteFunctions: any;

  beforeEach(() => {
    mockExecuteFunctions = {
      getNodeParameter: jest.fn(),
      getCredentials: jest.fn().mockResolvedValue({
        accessToken: 'test-token',
        baseUrl: 'https://api.crowdstrike.com'
      }),
      getInputData: jest.fn().mockReturnValue([{ json: {} }]),
      getNode: jest.fn().mockReturnValue({ name: 'Test Node' }),
      continueOnFail: jest.fn().mockReturnValue(false),
      helpers: {
        httpRequest: jest.fn(),
        requestWithAuthentication: jest.fn()
      },
    };
  });

  describe('queryVulnerabilities', () => {
    it('should query vulnerabilities successfully', async () => {
      const mockResponse = {
        meta: { query_time: 0.1, pagination: { offset: 0, limit: 100, total: 50 } },
        resources: ['vuln-123', 'vuln-456']
      };

      mockExecuteFunctions.getNodeParameter.mockImplementation((paramName: string) => {
        switch (paramName) {
          case 'operation': return 'queryVulnerabilities';
          case 'limit': return 100;
          case 'offset': return 0;
          case 'sort': return 'created_timestamp.desc';
          case 'filter': return 'severity:\'HIGH\'';
          default: return undefined;
        }
      });

      mockExecuteFunctions.helpers.httpRequest.mockResolvedValue(mockResponse);

      const result = await executeVulnerabilitiesOperations.call(mockExecuteFunctions, [{ json: {} }]);

      expect(result).toEqual([{ json: mockResponse, pairedItem: { item: 0 } }]);
      expect(mockExecuteFunctions.helpers.httpRequest).toHaveBeenCalledWith({
        method: 'GET',
        url: 'https://api.crowdstrike.com/spotlight/queries/vulnerabilities/v1?limit=100&offset=0&sort=created_timestamp.desc&filter=severity%3A%27HIGH%27',
        headers: {
          'Authorization': 'Bearer test-token',
          'Content-Type': 'application/json',
        },
        json: true,
      });
    });

    it('should handle query vulnerabilities error', async () => {
      mockExecuteFunctions.getNodeParameter.mockImplementation((paramName: string) => {
        switch (paramName) {
          case 'operation': return 'queryVulnerabilities';
          default: return undefined;
        }
      });

      mockExecuteFunctions.helpers.httpRequest.mockRejectedValue(new Error('API Error'));
      mockExecuteFunctions.continueOnFail.mockReturnValue(true);

      const result = await executeVulnerabilitiesOperations.call(mockExecuteFunctions, [{ json: {} }]);

      expect(result).toEqual([{ json: { error: 'API Error' }, pairedItem: { item: 0 } }]);
    });
  });

  describe('getVulnerabilities', () => {
    it('should get vulnerability details successfully', async () => {
      const mockResponse = {
        meta: { query_time: 0.1 },
        resources: [{ id: 'vuln-123', severity: 'HIGH', status: 'open' }]
      };

      mockExecuteFunctions.getNodeParameter.mockImplementation((paramName: string) => {
        switch (paramName) {
          case 'operation': return 'getVulnerabilities';
          case 'ids': return 'vuln-123,vuln-456';
          default: return undefined;
        }
      });

      mockExecuteFunctions.helpers.httpRequest.mockResolvedValue(mockResponse);

      const result = await executeVulnerabilitiesOperations.call(mockExecuteFunctions, [{ json: {} }]);

      expect(result).toEqual([{ json: mockResponse, pairedItem: { item: 0 } }]);
      expect(mockExecuteFunctions.helpers.httpRequest).toHaveBeenCalledWith({
        method: 'GET',
        url: 'https://api.crowdstrike.com/spotlight/entities/vulnerabilities/v2?ids=vuln-123%2Cvuln-456',
        headers: {
          'Authorization': 'Bearer test-token',
          'Content-Type': 'application/json',
        },
        json: true,
      });
    });
  });

  describe('getVulnerabilitiesCombined', () => {
    it('should get combined vulnerability data successfully', async () => {
      const mockResponse = {
        meta: { query_time: 0.1, pagination: { offset: 0, limit: 100, total: 25 } },
        resources: [{ id: 'vuln-123', severity: 'CRITICAL', status: 'open' }]
      };

      mockExecuteFunctions.getNodeParameter.mockImplementation((paramName: string) => {
        switch (paramName) {
          case 'operation': return 'getVulnerabilitiesCombined';
          case 'limit': return 100;
          case 'offset': return 0;
          case 'filter': return 'severity:\'CRITICAL\'';
          default: return undefined;
        }
      });

      mockExecuteFunctions.helpers.httpRequest.mockResolvedValue(mockResponse);

      const result = await executeVulnerabilitiesOperations.call(mockExecuteFunctions, [{ json: {} }]);

      expect(result).toEqual([{ json: mockResponse, pairedItem: { item: 0 } }]);
    });
  });
});

describe('EventStreams Resource', () => {
  let mockExecuteFunctions: any;

  beforeEach(() => {
    mockExecuteFunctions = {
      getNodeParameter: jest.fn(),
      getCredentials: jest.fn().mockResolvedValue({
        accessToken: 'test-token',
        baseUrl: 'https://api.crowdstrike.com'
      }),
      getInputData: jest.fn().mockReturnValue([{ json: {} }]),
      getNode: jest.fn().mockReturnValue({ name: 'Test Node' }),
      continueOnFail: jest.fn().mockReturnValue(false),
      helpers: {
        httpRequest: jest.fn(),
        requestWithAuthentication: jest.fn()
      },
    };
  });

  describe('createDataFeed operation', () => {
    it('should create data feed successfully', async () => {
      const mockResponse = { resources: [{ sessionToken: 'test-token' }] };
      mockExecuteFunctions.getNodeParameter
        .mockReturnValueOnce('createDataFeed')
        .mockReturnValueOnce('test-app-id');
      mockExecuteFunctions.helpers.httpRequest.mockResolvedValueOnce(mockResponse);

      const result = await executeEventStreamsOperations.call(mockExecuteFunctions, [{ json: {} }]);

      expect(result).toEqual([{ json: mockResponse, pairedItem: { item: 0 } }]);
      expect(mockExecuteFunctions.helpers.httpRequest).toHaveBeenCalledWith({
        method: 'POST',
        url: 'https://api.crowdstrike.com/sensors/entities/datafeed/v2',
        headers: {
          'Authorization': 'Bearer test-token',
          'Content-Type': 'application/json',
        },
        body: { appId: 'test-app-id' },
        json: true,
      });
    });

    it('should handle createDataFeed errors', async () => {
      mockExecuteFunctions.getNodeParameter
        .mockReturnValueOnce('createDataFeed')
        .mockReturnValueOnce('test-app-id');
      mockExecuteFunctions.helpers.httpRequest.mockRejectedValueOnce(new Error('API Error'));
      mockExecuteFunctions.continueOnFail.mockReturnValueOnce(true);

      const result = await executeEventStreamsOperations.call(mockExecuteFunctions, [{ json: {} }]);

      expect(result).toEqual([{ json: { error: 'API Error' }, pairedItem: { item: 0 } }]);
    });
  });

  describe('refreshDataFeed operation', () => {
    it('should refresh data feed successfully', async () => {
      const mockResponse = { resources: [{ events: [] }] };
      mockExecuteFunctions.getNodeParameter
        .mockReturnValueOnce('refreshDataFeed')
        .mockReturnValueOnce('test-app-id')
        .mockReturnValueOnce(0);
      mockExecuteFunctions.helpers.httpRequest.mockResolvedValueOnce(mockResponse);

      const result = await executeEventStreamsOperations.call(mockExecuteFunctions, [{ json: {} }]);

      expect(result).toEqual([{ json: mockResponse, pairedItem: { item: 0 } }]);
    });
  });

  describe('deleteDataFeed operation', () => {
    it('should delete data feed successfully', async () => {
      const mockResponse = { meta: { query_time: 0.001 } };
      mockExecuteFunctions.getNodeParameter
        .mockReturnValueOnce('deleteDataFeed')
        .mockReturnValueOnce('test-app-id');
      mockExecuteFunctions.helpers.httpRequest.mockResolvedValueOnce(mockResponse);

      const result = await executeEventStreamsOperations.call(mockExecuteFunctions, [{ json: {} }]);

      expect(result).toEqual([{ json: mockResponse, pairedItem: { item: 0 } }]);
    });
  });

  describe('getAWSSetupScripts operation', () => {
    it('should get AWS setup scripts successfully', async () => {
      const mockResponse = { resources: [{ script: 'aws script content' }] };
      mockExecuteFunctions.getNodeParameter
        .mockReturnValueOnce('getAWSSetupScripts')
        .mockReturnValueOnce('123456789,987654321');
      mockExecuteFunctions.helpers.httpRequest.mockResolvedValueOnce(mockResponse);

      const result = await executeEventStreamsOperations.call(mockExecuteFunctions, [{ json: {} }]);

      expect(result).toEqual([{ json: mockResponse, pairedItem: { item: 0 } }]);
    });
  });
});

describe('ThreatIntelligence Resource', () => {
  let mockExecuteFunctions: any;

  beforeEach(() => {
    mockExecuteFunctions = {
      getNodeParameter: jest.fn(),
      getCredentials: jest.fn().mockResolvedValue({
        accessToken: 'test-token',
        baseUrl: 'https://api.crowdstrike.com'
      }),
      getInputData: jest.fn().mockReturnValue([{ json: {} }]),
      getNode: jest.fn().mockReturnValue({ name: 'Test Node' }),
      continueOnFail: jest.fn().mockReturnValue(false),
      helpers: {
        httpRequest: jest.fn(),
        requestWithAuthentication: jest.fn(),
      },
    };
  });

  describe('Query Reports Operation', () => {
    it('should query threat intelligence reports successfully', async () => {
      mockExecuteFunctions.getNodeParameter.mockImplementation((param: string) => {
        switch (param) {
          case 'operation': return 'queryReports';
          case 'limit': return 100;
          case 'offset': return 0;
          case 'sort': return 'created_date.desc';
          case 'filter': return 'type:"intelligence-report"';
          default: return undefined;
        }
      });

      const mockResponse = {
        meta: { query_time: 0.1, powered_by: 'intel-api' },
        resources: ['report-id-1', 'report-id-2'],
      };

      mockExecuteFunctions.helpers.httpRequest.mockResolvedValue(mockResponse);

      const result = await executeThreatIntelligenceOperations.call(
        mockExecuteFunctions,
        [{ json: {} }]
      );

      expect(result).toHaveLength(1);
      expect(result[0].json).toEqual(mockResponse);
      expect(mockExecuteFunctions.helpers.httpRequest).toHaveBeenCalledWith({
        method: 'GET',
        url: 'https://api.crowdstrike.com/intel/queries/reports/v1?limit=100&offset=0&sort=created_date.desc&filter=type%3A%22intelligence-report%22',
        headers: {
          'Authorization': 'Bearer test-token',
          'Content-Type': 'application/json',
        },
        json: true,
      });
    });

    it('should handle query reports error', async () => {
      mockExecuteFunctions.getNodeParameter.mockImplementation((param: string) => {
        if (param === 'operation') return 'queryReports';
        return undefined;
      });
      mockExecuteFunctions.continueOnFail.mockReturnValue(true);
      mockExecuteFunctions.helpers.httpRequest.mockRejectedValue(new Error('API Error'));

      const result = await executeThreatIntelligenceOperations.call(
        mockExecuteFunctions,
        [{ json: {} }]
      );

      expect(result).toHaveLength(1);
      expect(result[0].json.error).toBe('API Error');
    });
  });

  describe('Get Reports Operation', () => {
    it('should get threat intelligence report details successfully', async () => {
      mockExecuteFunctions.getNodeParameter.mockImplementation((param: string) => {
        switch (param) {
          case 'operation': return 'getReports';
          case 'ids': return 'report-1,report-2';
          default: return undefined;
        }
      });

      const mockResponse = {
        meta: { query_time: 0.1, powered_by: 'intel-api' },
        resources: [
          { id: 'report-1', name: 'Threat Report 1' },
          { id: 'report-2', name: 'Threat Report 2' },
        ],
      };

      mockExecuteFunctions.helpers.httpRequest.mockResolvedValue(mockResponse);

      const result = await executeThreatIntelligenceOperations.call(
        mockExecuteFunctions,
        [{ json: {} }]
      );

      expect(result).toHaveLength(1);
      expect(result[0].json).toEqual(mockResponse);
    });
  });

  describe('Query Actors Operation', () => {
    it('should query threat actors successfully', async () => {
      mockExecuteFunctions.getNodeParameter.mockImplementation((param: string) => {
        switch (param) {
          case 'operation': return 'queryActors';
          case 'limit': return 50;
          case 'filter': return 'name:"APT*"';
          default: return undefined;
        }
      });

      const mockResponse = {
        meta: { query_time: 0.1, powered_by: 'intel-api' },
        resources: ['actor-id-1', 'actor-id-2'],
      };

      mockExecuteFunctions.helpers.httpRequest.mockResolvedValue(mockResponse);

      const result = await executeThreatIntelligenceOperations.call(
        mockExecuteFunctions,
        [{ json: {} }]
      );

      expect(result).toHaveLength(1);
      expect(result[0].json).toEqual(mockResponse);
    });
  });

  describe('Get Actors Operation', () => {
    it('should get threat actor details successfully', async () => {
      mockExecuteFunctions.getNodeParameter.mockImplementation((param: string) => {
        switch (param) {
          case 'operation': return 'getActors';
          case 'ids': return 'actor-1,actor-2';
          case 'fields': return 'name,description,origins';
          default: return undefined;
        }
      });

      const mockResponse = {
        meta: { query_time: 0.1, powered_by: 'intel-api' },
        resources: [
          { id: 'actor-1', name: 'APT1', description: 'Advanced Persistent Threat' },
          { id: 'actor-2', name: 'APT2', description: 'Another APT Group' },
        ],
      };

      mockExecuteFunctions.helpers.httpRequest.mockResolvedValue(mockResponse);

      const result = await executeThreatIntelligenceOperations.call(
        mockExecuteFunctions,
        [{ json: {} }]
      );

      expect(result).toHaveLength(1);
      expect(result[0].json).toEqual(mockResponse);
    });

    it('should handle get actors error', async () => {
      mockExecuteFunctions.getNodeParameter.mockImplementation((param: string) => {
        if (param === 'operation') return 'getActors';
        if (param === 'ids') return 'invalid-id';
        return undefined;
      });
      mockExecuteFunctions.continueOnFail.mockReturnValue(true);
      mockExecuteFunctions.helpers.httpRequest.mockRejectedValue(new Error('Actor not found'));

      const result = await executeThreatIntelligenceOperations.call(
        mockExecuteFunctions,
        [{ json: {} }]
      );

      expect(result).toHaveLength(1);
      expect(result[0].json.error).toBe('Actor not found');
    });
  });
});
});
