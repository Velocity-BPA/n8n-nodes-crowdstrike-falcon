/**
 * Copyright (c) 2026 Velocity BPA
 * 
 * Licensed under the Business Source License 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     https://github.com/VelocityBPA/n8n-nodes-crowdstrikefalcon/blob/main/LICENSE
 * 
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {
  IExecuteFunctions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
  NodeOperationError,
  NodeApiError,
} from 'n8n-workflow';

export class CrowdStrikeFalcon implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'CrowdStrike Falcon',
    name: 'crowdstrikefalcon',
    icon: 'file:crowdstrikefalcon.svg',
    group: ['transform'],
    version: 1,
    subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
    description: 'Interact with the CrowdStrike Falcon API',
    defaults: {
      name: 'CrowdStrike Falcon',
    },
    inputs: ['main'],
    outputs: ['main'],
    credentials: [
      {
        name: 'crowdstrikefalconApi',
        required: true,
      },
    ],
    properties: [
      {
        displayName: 'Resource',
        name: 'resource',
        type: 'options',
        noDataExpression: true,
        options: [
          {
            name: 'detections',
            value: 'detections',
          },
          {
            name: 'Incidents',
            value: 'incidents',
          },
          {
            name: 'Hosts',
            value: 'hosts',
          },
          {
            name: 'IOCs',
            value: 'iOCs',
          },
          {
            name: 'Vulnerabilities',
            value: 'vulnerabilities',
          },
          {
            name: 'EventStreams',
            value: 'eventStreams',
          },
          {
            name: 'ThreatIntelligence',
            value: 'threatIntelligence',
          }
        ],
        default: 'detections',
      },
{
  displayName: 'Operation',
  name: 'operation',
  type: 'options',
  noDataExpression: true,
  displayOptions: { show: { resource: ['detections'] } },
  options: [
    {
      name: 'Query Detections',
      value: 'queryDetections',
      description: 'Get detection IDs matching specified criteria',
      action: 'Query detections',
    },
    {
      name: 'Get Detections',
      value: 'getDetections',
      description: 'Get detection summaries for specified detection IDs',
      action: 'Get detections',
    },
    {
      name: 'Update Detections',
      value: 'updateDetections',
      description: 'Update detections with new status, assigned user, etc',
      action: 'Update detections',
    },
  ],
  default: 'queryDetections',
},
{
  displayName: 'Operation',
  name: 'operation',
  type: 'options',
  noDataExpression: true,
  displayOptions: { show: { resource: ['incidents'] } },
  options: [
    { name: 'Query Incidents', value: 'queryIncidents', description: 'Get incident IDs matching specified criteria', action: 'Query incidents' },
    { name: 'Get Incidents', value: 'getIncidents', description: 'Get incident details for specified incident IDs', action: 'Get incidents' },
    { name: 'Update Incidents', value: 'updateIncidents', description: 'Update incident status, severity, or other properties', action: 'Update incidents' },
    { name: 'Perform Incident Action', value: 'performIncidentAction', description: 'Perform actions on incidents like add tags or comments', action: 'Perform incident action' },
  ],
  default: 'queryIncidents',
},
{
  displayName: 'Operation',
  name: 'operation',
  type: 'options',
  noDataExpression: true,
  displayOptions: { show: { resource: ['hosts'] } },
  options: [
    { name: 'Query Devices', value: 'queryDevices', description: 'Get device IDs matching specified criteria', action: 'Query devices' },
    { name: 'Get Devices', value: 'getDevices', description: 'Get device details for specified device IDs', action: 'Get devices' },
    { name: 'Perform Device Action', value: 'performDeviceAction', description: 'Perform actions on devices like contain, lift containment, hide host', action: 'Perform device action' },
    { name: 'Query Devices Scroll', value: 'queryDevicesScroll', description: 'Get device IDs using scrolling for large datasets', action: 'Query devices with scroll' },
  ],
  default: 'queryDevices',
},
{
  displayName: 'Operation',
  name: 'operation',
  type: 'options',
  noDataExpression: true,
  displayOptions: { show: { resource: ['iOCs'] } },
  options: [
    { name: 'Query IOCs', value: 'queryIOCs', description: 'Get IOC IDs matching specified criteria', action: 'Query IOCs' },
    { name: 'Get IOCs', value: 'getIOCs', description: 'Get IOC details for specified IOC IDs', action: 'Get IOCs' },
    { name: 'Create IOCs', value: 'createIOCs', description: 'Create new custom IOCs', action: 'Create IOCs' },
    { name: 'Update IOCs', value: 'updateIOCs', description: 'Update existing IOCs', action: 'Update IOCs' },
    { name: 'Delete IOCs', value: 'deleteIOCs', description: 'Delete IOCs by IDs', action: 'Delete IOCs' },
  ],
  default: 'queryIOCs',
},
{
  displayName: 'Operation',
  name: 'operation',
  type: 'options',
  noDataExpression: true,
  displayOptions: { show: { resource: ['vulnerabilities'] } },
  options: [
    { name: 'Query Vulnerabilities', value: 'queryVulnerabilities', description: 'Get vulnerability IDs matching specified criteria', action: 'Query vulnerabilities' },
    { name: 'Get Vulnerabilities', value: 'getVulnerabilities', description: 'Get vulnerability details for specified vulnerability IDs', action: 'Get vulnerabilities' },
    { name: 'Get Vulnerabilities Combined', value: 'getVulnerabilitiesCombined', description: 'Get vulnerability details in single request', action: 'Get vulnerabilities combined' }
  ],
  default: 'queryVulnerabilities',
},
{
  displayName: 'Operation',
  name: 'operation',
  type: 'options',
  noDataExpression: true,
  displayOptions: { show: { resource: ['eventStreams'] } },
  options: [
    { name: 'Create Data Feed', value: 'createDataFeed', description: 'Create new data feed session', action: 'Create data feed' },
    { name: 'Refresh Data Feed', value: 'refreshDataFeed', description: 'Refresh active data feed session', action: 'Refresh data feed' },
    { name: 'Delete Data Feed', value: 'deleteDataFeed', description: 'Delete data feed session', action: 'Delete data feed' },
    { name: 'Get AWS Setup Scripts', value: 'getAWSSetupScripts', description: 'Get AWS account setup scripts', action: 'Get AWS setup scripts' },
  ],
  default: 'createDataFeed',
},
{
  displayName: 'Operation',
  name: 'operation',
  type: 'options',
  noDataExpression: true,
  displayOptions: { show: { resource: ['threatIntelligence'] } },
  options: [
    { name: 'Query Reports', value: 'queryReports', description: 'Get threat intelligence report IDs', action: 'Query threat intelligence reports' },
    { name: 'Get Reports', value: 'getReports', description: 'Get threat intelligence report details', action: 'Get threat intelligence reports' },
    { name: 'Query Actors', value: 'queryActors', description: 'Get threat actor IDs', action: 'Query threat actors' },
    { name: 'Get Actors', value: 'getActors', description: 'Get threat actor details', action: 'Get threat actors' },
  ],
  default: 'queryReports',
},
{
  displayName: 'Limit',
  name: 'limit',
  type: 'number',
  displayOptions: {
    show: {
      resource: ['detections'],
      operation: ['queryDetections'],
    },
  },
  default: 100,
  description: 'Maximum number of detection IDs to return',
},
{
  displayName: 'Offset',
  name: 'offset',
  type: 'number',
  displayOptions: {
    show: {
      resource: ['detections'],
      operation: ['queryDetections'],
    },
  },
  default: 0,
  description: 'Starting index of overall result set',
},
{
  displayName: 'Sort',
  name: 'sort',
  type: 'string',
  displayOptions: {
    show: {
      resource: ['detections'],
      operation: ['queryDetections'],
    },
  },
  default: '',
  description: 'Sort expression for detection ordering',
},
{
  displayName: 'Filter',
  name: 'filter',
  type: 'string',
  displayOptions: {
    show: {
      resource: ['detections'],
      operation: ['queryDetections'],
    },
  },
  default: '',
  description: 'FQL (Falcon Query Language) expression to filter detections',
},
{
  displayName: 'Detection IDs',
  name: 'ids',
  type: 'string',
  displayOptions: {
    show: {
      resource: ['detections'],
      operation: ['getDetections'],
    },
  },
  required: true,
  default: '',
  description: 'Comma-separated list of detection IDs to retrieve',
},
{
  displayName: 'Detection IDs',
  name: 'ids',
  type: 'string',
  displayOptions: {
    show: {
      resource: ['detections'],
      operation: ['updateDetections'],
    },
  },
  required: true,
  default: '',
  description: 'Comma-separated list of detection IDs to update',
},
{
  displayName: 'Status',
  name: 'status',
  type: 'options',
  displayOptions: {
    show: {
      resource: ['detections'],
      operation: ['updateDetections'],
    },
  },
  options: [
    {
      name: 'New',
      value: 'new',
    },
    {
      name: 'In Progress',
      value: 'in_progress',
    },
    {
      name: 'True Positive',
      value: 'true_positive',
    },
    {
      name: 'False Positive',
      value: 'false_positive',
    },
    {
      name: 'Ignored',
      value: 'ignored',
    },
  ],
  default: '',
  description: 'New status for the detections',
},
{
  displayName: 'Assigned To UUID',
  name: 'assigned_to_uuid',
  type: 'string',
  displayOptions: {
    show: {
      resource: ['detections'],
      operation: ['updateDetections'],
    },
  },
  default: '',
  description: 'UUID of the user to assign the detections to',
},
{
  displayName: 'Limit',
  name: 'limit',
  type: 'number',
  default: 100,
  description: 'Maximum number of incidents to return',
  displayOptions: { 
    show: { 
      resource: ['incidents'], 
      operation: ['queryIncidents'] 
    } 
  },
},
{
  displayName: 'Offset',
  name: 'offset',
  type: 'number',
  default: 0,
  description: 'Starting index of the result set',
  displayOptions: { 
    show: { 
      resource: ['incidents'], 
      operation: ['queryIncidents'] 
    } 
  },
},
{
  displayName: 'Sort',
  name: 'sort',
  type: 'string',
  default: '',
  placeholder: 'created_timestamp.desc',
  description: 'Sort order for results (e.g., created_timestamp.desc)',
  displayOptions: { 
    show: { 
      resource: ['incidents'], 
      operation: ['queryIncidents'] 
    } 
  },
},
{
  displayName: 'Filter',
  name: 'filter',
  type: 'string',
  default: '',
  placeholder: 'status:\'open\'',
  description: 'FQL filter expression to match incidents',
  displayOptions: { 
    show: { 
      resource: ['incidents'], 
      operation: ['queryIncidents'] 
    } 
  },
},
{
  displayName: 'Incident IDs',
  name: 'ids',
  type: 'string',
  required: true,
  default: '',
  placeholder: 'inc:12345,inc:67890',
  description: 'Comma-separated list of incident IDs',
  displayOptions: { 
    show: { 
      resource: ['incidents'], 
      operation: ['getIncidents', 'updateIncidents', 'performIncidentAction'] 
    } 
  },
},
{
  displayName: 'Status',
  name: 'status',
  type: 'options',
  default: 'open',
  options: [
    { name: 'Open', value: 'open' },
    { name: 'In Progress', value: 'in_progress' },
    { name: 'Closed', value: 'closed' },
    { name: 'Reopened', value: 'reopened' },
  ],
  description: 'New status for the incident',
  displayOptions: { 
    show: { 
      resource: ['incidents'], 
      operation: ['updateIncidents'] 
    } 
  },
},
{
  displayName: 'Severity',
  name: 'severity',
  type: 'options',
  default: 'medium',
  options: [
    { name: 'Low', value: 'low' },
    { name: 'Medium', value: 'medium' },
    { name: 'High', value: 'high' },
    { name: 'Critical', value: 'critical' },
  ],
  description: 'New severity level for the incident',
  displayOptions: { 
    show: { 
      resource: ['incidents'], 
      operation: ['updateIncidents'] 
    } 
  },
},
{
  displayName: 'Action Parameters',
  name: 'actionParameters',
  type: 'json',
  default: '{}',
  description: 'JSON object containing action parameters (e.g., {"add_tag": "priority", "comment": "Investigation started"})',
  displayOptions: { 
    show: { 
      resource: ['incidents'], 
      operation: ['performIncidentAction'] 
    } 
  },
},
{
  displayName: 'Limit',
  name: 'limit',
  type: 'number',
  default: 100,
  description: 'Maximum number of results to return',
  displayOptions: {
    show: {
      resource: ['hosts'],
      operation: ['queryDevices', 'queryDevicesScroll'],
    },
  },
},
{
  displayName: 'Offset',
  name: 'offset',
  type: 'number',
  default: 0,
  description: 'Starting index for results',
  displayOptions: {
    show: {
      resource: ['hosts'],
      operation: ['queryDevices', 'queryDevicesScroll'],
    },
  },
},
{
  displayName: 'Sort',
  name: 'sort',
  type: 'string',
  default: '',
  placeholder: 'hostname.asc',
  description: 'Sort results by field and direction (e.g., hostname.asc)',
  displayOptions: {
    show: {
      resource: ['hosts'],
      operation: ['queryDevices'],
    },
  },
},
{
  displayName: 'Filter',
  name: 'filter',
  type: 'string',
  default: '',
  placeholder: 'platform_name:"Windows"',
  description: 'FQL filter expression to match devices',
  displayOptions: {
    show: {
      resource: ['hosts'],
      operation: ['queryDevices', 'queryDevicesScroll'],
    },
  },
},
{
  displayName: 'Device IDs',
  name: 'ids',
  type: 'string',
  required: true,
  default: '',
  placeholder: 'device_id_1,device_id_2',
  description: 'Comma-separated list of device IDs',
  displayOptions: {
    show: {
      resource: ['hosts'],
      operation: ['getDevices', 'performDeviceAction'],
    },
  },
},
{
  displayName: 'Action Name',
  name: 'action_name',
  type: 'options',
  required: true,
  options: [
    { name: 'Contain', value: 'contain', description: 'Contain the device' },
    { name: 'Lift Containment', value: 'lift_containment', description: 'Lift containment from the device' },
    { name: 'Hide Host', value: 'hide_host', description: 'Hide the host from the console' },
    { name: 'Unhide Host', value: 'unhide_host', description: 'Unhide the host in the console' },
  ],
  default: 'contain',
  description: 'Action to perform on the devices',
  displayOptions: {
    show: {
      resource: ['hosts'],
      operation: ['performDeviceAction'],
    },
  },
},
{
  displayName: 'Limit',
  name: 'limit',
  type: 'number',
  displayOptions: { show: { resource: ['iOCs'], operation: ['queryIOCs'] } },
  default: 100,
  description: 'Maximum number of IOC IDs to return',
},
{
  displayName: 'Offset',
  name: 'offset',
  type: 'number',
  displayOptions: { show: { resource: ['iOCs'], operation: ['queryIOCs'] } },
  default: 0,
  description: 'Starting index for pagination',
},
{
  displayName: 'Sort',
  name: 'sort',
  type: 'string',
  displayOptions: { show: { resource: ['iOCs'], operation: ['queryIOCs'] } },
  default: '',
  description: 'Property to sort by',
},
{
  displayName: 'Filter',
  name: 'filter',
  type: 'string',
  displayOptions: { show: { resource: ['iOCs'], operation: ['queryIOCs'] } },
  default: '',
  description: 'FQL query to filter IOCs',
},
{
  displayName: 'Types',
  name: 'types',
  type: 'string',
  displayOptions: { show: { resource: ['iOCs'], operation: ['queryIOCs'] } },
  default: '',
  description: 'Comma-separated list of IOC types to query',
},
{
  displayName: 'IOC IDs',
  name: 'ids',
  type: 'string',
  displayOptions: { show: { resource: ['iOCs'], operation: ['getIOCs', 'deleteIOCs'] } },
  required: true,
  default: '',
  description: 'Comma-separated list of IOC IDs',
},
{
  displayName: 'Indicators',
  name: 'indicators',
  type: 'json',
  displayOptions: { show: { resource: ['iOCs'], operation: ['createIOCs', 'updateIOCs'] } },
  required: true,
  default: '[]',
  description: 'Array of IOC indicators to create or update',
},
{
  displayName: 'Limit',
  name: 'limit',
  type: 'number',
  displayOptions: { show: { resource: ['vulnerabilities'], operation: ['queryVulnerabilities', 'getVulnerabilitiesCombined'] } },
  default: 100,
  description: 'Maximum number of results to return',
},
{
  displayName: 'Offset',
  name: 'offset',
  type: 'number',
  displayOptions: { show: { resource: ['vulnerabilities'], operation: ['queryVulnerabilities', 'getVulnerabilitiesCombined'] } },
  default: 0,
  description: 'Starting index of results to return',
},
{
  displayName: 'Sort',
  name: 'sort',
  type: 'string',
  displayOptions: { show: { resource: ['vulnerabilities'], operation: ['queryVulnerabilities', 'getVulnerabilitiesCombined'] } },
  default: '',
  placeholder: 'created_timestamp.desc',
  description: 'Sort expression for ordering results',
},
{
  displayName: 'Filter',
  name: 'filter',
  type: 'string',
  displayOptions: { show: { resource: ['vulnerabilities'], operation: ['queryVulnerabilities', 'getVulnerabilitiesCombined'] } },
  default: '',
  placeholder: 'severity:\'HIGH\'+status:\'open\'',
  description: 'FQL (Falcon Query Language) expression to filter results',
},
{
  displayName: 'Vulnerability IDs',
  name: 'ids',
  type: 'string',
  displayOptions: { show: { resource: ['vulnerabilities'], operation: ['getVulnerabilities'] } },
  required: true,
  default: '',
  placeholder: 'vuln-123,vuln-456',
  description: 'Comma-separated list of vulnerability IDs to retrieve details for',
},
{
  displayName: 'App ID',
  name: 'appId',
  type: 'string',
  required: true,
  displayOptions: {
    show: {
      resource: ['eventStreams'],
      operation: ['createDataFeed']
    }
  },
  default: '',
  description: 'The application ID for the data feed',
},
{
  displayName: 'App ID',
  name: 'appId',
  type: 'string',
  required: true,
  displayOptions: {
    show: {
      resource: ['eventStreams'],
      operation: ['refreshDataFeed']
    }
  },
  default: '',
  description: 'The application ID for the data feed',
},
{
  displayName: 'Partition',
  name: 'partition',
  type: 'number',
  required: false,
  displayOptions: {
    show: {
      resource: ['eventStreams'],
      operation: ['refreshDataFeed']
    }
  },
  default: 0,
  description: 'The partition number for the data feed',
},
{
  displayName: 'App ID',
  name: 'appId',
  type: 'string',
  required: true,
  displayOptions: {
    show: {
      resource: ['eventStreams'],
      operation: ['deleteDataFeed']
    }
  },
  default: '',
  description: 'The application ID for the data feed to delete',
},
{
  displayName: 'Accounts',
  name: 'accounts',
  type: 'string',
  required: true,
  displayOptions: {
    show: {
      resource: ['eventStreams'],
      operation: ['getAWSSetupScripts']
    }
  },
  default: '',
  description: 'AWS account IDs (comma-separated)',
},
{
  displayName: 'Limit',
  name: 'limit',
  type: 'number',
  default: 100,
  description: 'Maximum number of results to return',
  displayOptions: { show: { resource: ['threatIntelligence'], operation: ['queryReports', 'queryActors'] } },
},
{
  displayName: 'Offset',
  name: 'offset',
  type: 'number',
  default: 0,
  description: 'Starting position for pagination',
  displayOptions: { show: { resource: ['threatIntelligence'], operation: ['queryReports', 'queryActors'] } },
},
{
  displayName: 'Sort',
  name: 'sort',
  type: 'string',
  default: '',
  placeholder: 'field.asc or field.desc',
  description: 'Sort order for results',
  displayOptions: { show: { resource: ['threatIntelligence'], operation: ['queryReports', 'queryActors'] } },
},
{
  displayName: 'Filter',
  name: 'filter',
  type: 'string',
  default: '',
  placeholder: 'field:"value"',
  description: 'FQL filter for results',
  displayOptions: { show: { resource: ['threatIntelligence'], operation: ['queryReports', 'queryActors'] } },
},
{
  displayName: 'Report IDs',
  name: 'ids',
  type: 'string',
  required: true,
  default: '',
  placeholder: 'id1,id2,id3',
  description: 'Comma-separated list of report IDs',
  displayOptions: { show: { resource: ['threatIntelligence'], operation: ['getReports'] } },
},
{
  displayName: 'Actor IDs',
  name: 'ids',
  type: 'string',
  required: true,
  default: '',
  placeholder: 'id1,id2,id3',
  description: 'Comma-separated list of actor IDs',
  displayOptions: { show: { resource: ['threatIntelligence'], operation: ['getActors'] } },
},
{
  displayName: 'Fields',
  name: 'fields',
  type: 'string',
  default: '',
  placeholder: 'field1,field2,field3',
  description: 'Comma-separated list of fields to include in response',
  displayOptions: { show: { resource: ['threatIntelligence'], operation: ['getActors'] } },
},
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const resource = this.getNodeParameter('resource', 0) as string;

    switch (resource) {
      case 'detections':
        return [await executedetectionsOperations.call(this, items)];
      case 'incidents':
        return [await executeIncidentsOperations.call(this, items)];
      case 'hosts':
        return [await executeHostsOperations.call(this, items)];
      case 'iOCs':
        return [await executeIOCsOperations.call(this, items)];
      case 'vulnerabilities':
        return [await executeVulnerabilitiesOperations.call(this, items)];
      case 'eventStreams':
        return [await executeEventStreamsOperations.call(this, items)];
      case 'threatIntelligence':
        return [await executeThreatIntelligenceOperations.call(this, items)];
      default:
        throw new NodeOperationError(this.getNode(), `The resource "${resource}" is not supported`);
    }
  }
}

// ============================================================
// Resource Handler Functions
// ============================================================

async function executeDetectionsOperations(
  this: IExecuteFunctions,
  items: INodeExecutionData[],
): Promise<INodeExecutionData[]> {
  const returnData: INodeExecutionData[] = [];
  const operation = this.getNodeParameter('operation', 0) as string;
  const credentials = await this.getCredentials('crowdstrikefalconApi') as any;

  for (let i = 0; i < items.length; i++) {
    try {
      let result: any;

      switch (operation) {
        case 'queryDetections': {
          const limit = this.getNodeParameter('limit', i) as number;
          const offset = this.getNodeParameter('offset', i) as number;
          const sort = this.getNodeParameter('sort', i) as string;
          const filter = this.getNodeParameter('filter', i) as string;

          const queryParams: any = {};
          if (limit) queryParams.limit = limit;
          if (offset) queryParams.offset = offset;
          if (sort) queryParams.sort = sort;
          if (filter) queryParams.filter = filter;

          const options: any = {
            method: 'GET',
            url: `${credentials.baseUrl}/detects/queries/detects/v1`,
            headers: {
              Authorization: `Bearer ${credentials.accessToken}`,
              'Content-Type': 'application/json',
            },
            qs: queryParams,
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'getDetections': {
          const ids = this.getNodeParameter('ids', i) as string;
          const idArray = ids.split(',').map((id: string) => id.trim());

          const options: any = {
            method: 'POST',
            url: `${credentials.baseUrl}/detects/entities/summaries/GET/v1`,
            headers: {
              Authorization: `Bearer ${credentials.accessToken}`,
              'Content-Type': 'application/json',
            },
            body: {
              ids: idArray,
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'updateDetections': {
          const ids = this.getNodeParameter('ids', i) as string;
          const status = this.getNodeParameter('status', i) as string;
          const assignedToUuid = this.getNodeParameter('assigned_to_uuid', i) as string;
          const idArray = ids.split(',').map((id: string) => id.trim());

          const body: any = {
            ids: idArray,
          };

          if (status) body.status = status;
          if (assignedToUuid) body.assigned_to_uuid = assignedToUuid;

          const options: any = {
            method: 'PATCH',
            url: `${credentials.baseUrl}/detects/entities/detects/v2`,
            headers: {
              Authorization: `Bearer ${credentials.accessToken}`,
              'Content-Type': 'application/json',
            },
            body: body,
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        default:
          throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`);
      }

      returnData.push({
        json: result,
        pairedItem: { item: i },
      });
    } catch (error: any) {
      if (this.continueOnFail()) {
        returnData.push({
          json: { error: error.message },
          pairedItem: { item: i },
        });
      } else {
        throw error;
      }
    }
  }

  return returnData;
}

async function executeIncidentsOperations(
  this: IExecuteFunctions,
  items: INodeExecutionData[],
): Promise<INodeExecutionData[]> {
  const returnData: INodeExecutionData[] = [];
  const operation = this.getNodeParameter('operation', 0) as string;
  const credentials = await this.getCredentials('crowdstrikefalconApi') as any;

  for (let i = 0; i < items.length; i++) {
    try {
      let result: any;

      switch (operation) {
        case 'queryIncidents': {
          const limit = this.getNodeParameter('limit', i) as number;
          const offset = this.getNodeParameter('offset', i) as number;
          const sort = this.getNodeParameter('sort', i) as string;
          const filter = this.getNodeParameter('filter', i) as string;

          const queryParams = new URLSearchParams();
          queryParams.append('limit', limit.toString());
          queryParams.append('offset', offset.toString());
          if (sort) queryParams.append('sort', sort);
          if (filter) queryParams.append('filter', filter);

          const options: any = {
            method: 'GET',
            url: `${credentials.baseUrl}/incidents/queries/incidents/v1?${queryParams.toString()}`,
            headers: {
              'Authorization': `Bearer ${credentials.accessToken}`,
              'Content-Type': 'application/json',
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'getIncidents': {
          const ids = this.getNodeParameter('ids', i) as string;
          const idsArray = ids.split(',').map(id => id.trim());

          const options: any = {
            method: 'GET',
            url: `${credentials.baseUrl}/incidents/entities/incidents/GET/v1`,
            headers: {
              'Authorization': `Bearer ${credentials.accessToken}`,
              'Content-Type': 'application/json',
            },
            body: {
              ids: idsArray,
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'updateIncidents': {
          const ids = this.getNodeParameter('ids', i) as string;
          const status = this.getNodeParameter('status', i) as string;
          const severity = this.getNodeParameter('severity', i) as string;
          const idsArray = ids.split(',').map(id => id.trim());

          const updateData = idsArray.map(id => ({
            id,
            status,
            severity,
          }));

          const options: any = {
            method: 'PATCH',
            url: `${credentials.baseUrl}/incidents/entities/incidents/v1`,
            headers: {
              'Authorization': `Bearer ${credentials.accessToken}`,
              'Content-Type': 'application/json',
            },
            body: {
              incidents: updateData,
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'performIncidentAction': {
          const ids = this.getNodeParameter('ids', i) as string;
          const actionParameters = this.getNodeParameter('actionParameters', i) as string;
          const idsArray = ids.split(',').map(id => id.trim());

          let parsedActionParameters: any = {};
          try {
            parsedActionParameters = JSON.parse(actionParameters);
          } catch (error: any) {
            throw new NodeOperationError(this.getNode(), `Invalid JSON in action parameters: ${error.message}`);
          }

          const options: any = {
            method: 'POST',
            url: `${credentials.baseUrl}/incidents/entities/incident-actions/v1`,
            headers: {
              'Authorization': `Bearer ${credentials.accessToken}`,
              'Content-Type': 'application/json',
            },
            body: {
              ids: idsArray,
              action_parameters: parsedActionParameters,
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        default:
          throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`);
      }

      returnData.push({
        json: result,
        pairedItem: { item: i },
      });

    } catch (error: any) {
      if (this.continueOnFail()) {
        returnData.push({
          json: { error: error.message },
          pairedItem: { item: i },
        });
      } else {
        throw error;
      }
    }
  }

  return returnData;
}

async function executeHostsOperations(
  this: IExecuteFunctions,
  items: INodeExecutionData[],
): Promise<INodeExecutionData[]> {
  const returnData: INodeExecutionData[] = [];
  const operation = this.getNodeParameter('operation', 0) as string;
  const credentials = await this.getCredentials('crowdstrikefalconApi') as any;

  for (let i = 0; i < items.length; i++) {
    try {
      let result: any;

      switch (operation) {
        case 'queryDevices': {
          const limit = this.getNodeParameter('limit', i) as number;
          const offset = this.getNodeParameter('offset', i) as number;
          const sort = this.getNodeParameter('sort', i) as string;
          const filter = this.getNodeParameter('filter', i) as string;

          const params = new URLSearchParams();
          if (limit) params.append('limit', limit.toString());
          if (offset) params.append('offset', offset.toString());
          if (sort) params.append('sort', sort);
          if (filter) params.append('filter', filter);

          const options: any = {
            method: 'GET',
            url: `${credentials.baseUrl}/devices/queries/devices/v1?${params.toString()}`,
            headers: {
              'Authorization': `Bearer ${credentials.access_token}`,
              'Content-Type': 'application/json',
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'getDevices': {
          const ids = this.getNodeParameter('ids', i) as string;
          const deviceIds = ids.split(',').map((id: string) => id.trim());

          const params = new URLSearchParams();
          deviceIds.forEach((id: string) => params.append('ids', id));

          const options: any = {
            method: 'GET',
            url: `${credentials.baseUrl}/devices/entities/devices/v2?${params.toString()}`,
            headers: {
              'Authorization': `Bearer ${credentials.access_token}`,
              'Content-Type': 'application/json',
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'performDeviceAction': {
          const ids = this.getNodeParameter('ids', i) as string;
          const actionName = this.getNodeParameter('action_name', i) as string;
          const deviceIds = ids.split(',').map((id: string) => id.trim());

          const params = new URLSearchParams();
          params.append('action_name', actionName);

          const options: any = {
            method: 'POST',
            url: `${credentials.baseUrl}/devices/entities/devices-actions/v2?${params.toString()}`,
            headers: {
              'Authorization': `Bearer ${credentials.access_token}`,
              'Content-Type': 'application/json',
            },
            body: {
              ids: deviceIds,
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'queryDevicesScroll': {
          const limit = this.getNodeParameter('limit', i) as number;
          const offset = this.getNodeParameter('offset', i) as number;
          const filter = this.getNodeParameter('filter', i) as string;

          const params = new URLSearchParams();
          if (limit) params.append('limit', limit.toString());
          if (offset) params.append('offset', offset.toString());
          if (filter) params.append('filter', filter);

          const options: any = {
            method: 'GET',
            url: `${credentials.baseUrl}/devices/queries/devices-scroll/v1?${params.toString()}`,
            headers: {
              'Authorization': `Bearer ${credentials.access_token}`,
              'Content-Type': 'application/json',
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        default:
          throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`);
      }

      returnData.push({
        json: result,
        pairedItem: { item: i },
      });
    } catch (error: any) {
      if (this.continueOnFail()) {
        returnData.push({
          json: { error: error.message },
          pairedItem: { item: i },
        });
      } else {
        throw error;
      }
    }
  }

  return returnData;
}

async function executeIOCsOperations(
  this: IExecuteFunctions,
  items: INodeExecutionData[],
): Promise<INodeExecutionData[]> {
  const returnData: INodeExecutionData[] = [];
  const operation = this.getNodeParameter('operation', 0) as string;
  const credentials = await this.getCredentials('crowdstrikefalconApi') as any;

  for (let i = 0; i < items.length; i++) {
    try {
      let result: any;

      switch (operation) {
        case 'queryIOCs': {
          const limit = this.getNodeParameter('limit', i, 100) as number;
          const offset = this.getNodeParameter('offset', i, 0) as number;
          const sort = this.getNodeParameter('sort', i, '') as string;
          const filter = this.getNodeParameter('filter', i, '') as string;
          const types = this.getNodeParameter('types', i, '') as string;

          const queryParams = new URLSearchParams();
          if (limit) queryParams.append('limit', limit.toString());
          if (offset) queryParams.append('offset', offset.toString());
          if (sort) queryParams.append('sort', sort);
          if (filter) queryParams.append('filter', filter);
          if (types) queryParams.append('types', types);

          const options: any = {
            method: 'GET',
            url: `${credentials.baseUrl}/iocs/queries/indicators/v1?${queryParams.toString()}`,
            headers: {
              'Authorization': `Bearer ${credentials.accessToken}`,
              'Content-Type': 'application/json',
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'getIOCs': {
          const ids = this.getNodeParameter('ids', i) as string;

          const queryParams = new URLSearchParams();
          queryParams.append('ids', ids);

          const options: any = {
            method: 'GET',
            url: `${credentials.baseUrl}/iocs/entities/indicators/v1?${queryParams.toString()}`,
            headers: {
              'Authorization': `Bearer ${credentials.accessToken}`,
              'Content-Type': 'application/json',
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'createIOCs': {
          const indicators = this.getNodeParameter('indicators', i) as string;
          let parsedIndicators: any;

          try {
            parsedIndicators = JSON.parse(indicators);
          } catch (parseError: any) {
            throw new NodeOperationError(this.getNode(), `Invalid JSON in indicators: ${parseError.message}`);
          }

          const options: any = {
            method: 'POST',
            url: `${credentials.baseUrl}/iocs/entities/indicators/v1`,
            headers: {
              'Authorization': `Bearer ${credentials.accessToken}`,
              'Content-Type': 'application/json',
            },
            body: {
              indicators: parsedIndicators,
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'updateIOCs': {
          const indicators = this.getNodeParameter('indicators', i) as string;
          let parsedIndicators: any;

          try {
            parsedIndicators = JSON.parse(indicators);
          } catch (parseError: any) {
            throw new NodeOperationError(this.getNode(), `Invalid JSON in indicators: ${parseError.message}`);
          }

          const options: any = {
            method: 'PATCH',
            url: `${credentials.baseUrl}/iocs/entities/indicators/v1`,
            headers: {
              'Authorization': `Bearer ${credentials.accessToken}`,
              'Content-Type': 'application/json',
            },
            body: {
              indicators: parsedIndicators,
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'deleteIOCs': {
          const ids = this.getNodeParameter('ids', i) as string;

          const queryParams = new URLSearchParams();
          queryParams.append('ids', ids);

          const options: any = {
            method: 'DELETE',
            url: `${credentials.baseUrl}/iocs/entities/indicators/v1?${queryParams.toString()}`,
            headers: {
              'Authorization': `Bearer ${credentials.accessToken}`,
              'Content-Type': 'application/json',
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        default:
          throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`);
      }

      returnData.push({ json: result, pairedItem: { item: i } });
    } catch (error: any) {
      if (this.continueOnFail()) {
        returnData.push({ json: { error: error.message }, pairedItem: { item: i } });
      } else {
        throw error;
      }
    }
  }

  return returnData;
}

async function executeVulnerabilitiesOperations(
  this: IExecuteFunctions,
  items: INodeExecutionData[],
): Promise<INodeExecutionData[]> {
  const returnData: INodeExecutionData[] = [];
  const operation = this.getNodeParameter('operation', 0) as string;
  const credentials = await this.getCredentials('crowdstrikefalconApi') as any;

  for (let i = 0; i < items.length; i++) {
    try {
      let result: any;

      switch (operation) {
        case 'queryVulnerabilities': {
          const limit = this.getNodeParameter('limit', i) as number;
          const offset = this.getNodeParameter('offset', i) as number;
          const sort = this.getNodeParameter('sort', i) as string;
          const filter = this.getNodeParameter('filter', i) as string;

          const queryParams = new URLSearchParams();
          if (limit) queryParams.append('limit', limit.toString());
          if (offset) queryParams.append('offset', offset.toString());
          if (sort) queryParams.append('sort', sort);
          if (filter) queryParams.append('filter', filter);

          const options: any = {
            method: 'GET',
            url: `${credentials.baseUrl}/spotlight/queries/vulnerabilities/v1?${queryParams.toString()}`,
            headers: {
              'Authorization': `Bearer ${credentials.accessToken}`,
              'Content-Type': 'application/json',
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'getVulnerabilities': {
          const ids = this.getNodeParameter('ids', i) as string;
          
          const queryParams = new URLSearchParams();
          queryParams.append('ids', ids);

          const options: any = {
            method: 'GET',
            url: `${credentials.baseUrl}/spotlight/entities/vulnerabilities/v2?${queryParams.toString()}`,
            headers: {
              'Authorization': `Bearer ${credentials.accessToken}`,
              'Content-Type': 'application/json',
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'getVulnerabilitiesCombined': {
          const limit = this.getNodeParameter('limit', i) as number;
          const offset = this.getNodeParameter('offset', i) as number;
          const sort = this.getNodeParameter('sort', i) as string;
          const filter = this.getNodeParameter('filter', i) as string;

          const queryParams = new URLSearchParams();
          if (limit) queryParams.append('limit', limit.toString());
          if (offset) queryParams.append('offset', offset.toString());
          if (sort) queryParams.append('sort', sort);
          if (filter) queryParams.append('filter', filter);

          const options: any = {
            method: 'GET',
            url: `${credentials.baseUrl}/spotlight/combined/vulnerabilities/v1?${queryParams.toString()}`,
            headers: {
              'Authorization': `Bearer ${credentials.accessToken}`,
              'Content-Type': 'application/json',
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        default:
          throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`);
      }

      returnData.push({
        json: result,
        pairedItem: { item: i },
      });

    } catch (error: any) {
      if (this.continueOnFail()) {
        returnData.push({
          json: { error: error.message },
          pairedItem: { item: i },
        });
      } else {
        throw error;
      }
    }
  }

  return returnData;
}

async function executeEventStreamsOperations(
  this: IExecuteFunctions,
  items: INodeExecutionData[],
): Promise<INodeExecutionData[]> {
  const returnData: INodeExecutionData[] = [];
  const operation = this.getNodeParameter('operation', 0) as string;
  const credentials = await this.getCredentials('crowdstrikefalconApi') as any;

  for (let i = 0; i < items.length; i++) {
    try {
      let result: any;

      switch (operation) {
        case 'createDataFeed': {
          const appId = this.getNodeParameter('appId', i) as string;
          
          const options: any = {
            method: 'POST',
            url: `${credentials.baseUrl}/sensors/entities/datafeed/v2`,
            headers: {
              'Authorization': `Bearer ${credentials.accessToken}`,
              'Content-Type': 'application/json',
            },
            body: {
              appId: appId,
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'refreshDataFeed': {
          const appId = this.getNodeParameter('appId', i) as string;
          const partition = this.getNodeParameter('partition', i) as number;

          const queryParams = new URLSearchParams();
          queryParams.append('appId', appId);
          if (partition !== undefined) {
            queryParams.append('partition', partition.toString());
          }

          const options: any = {
            method: 'GET',
            url: `${credentials.baseUrl}/sensors/entities/datafeed/v2?${queryParams.toString()}`,
            headers: {
              'Authorization': `Bearer ${credentials.accessToken}`,
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'deleteDataFeed': {
          const appId = this.getNodeParameter('appId', i) as string;

          const queryParams = new URLSearchParams();
          queryParams.append('appId', appId);

          const options: any = {
            method: 'DELETE',
            url: `${credentials.baseUrl}/sensors/entities/datafeed/v2?${queryParams.toString()}`,
            headers: {
              'Authorization': `Bearer ${credentials.accessToken}`,
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        case 'getAWSSetupScripts': {
          const accounts = this.getNodeParameter('accounts', i) as string;

          const queryParams = new URLSearchParams();
          queryParams.append('accounts', accounts);

          const options: any = {
            method: 'GET',
            url: `${credentials.baseUrl}/sensors/entities/datafeed-actions/v1/getAWSAccountScripts?${queryParams.toString()}`,
            headers: {
              'Authorization': `Bearer ${credentials.accessToken}`,
            },
            json: true,
          };

          result = await this.helpers.httpRequest(options) as any;
          break;
        }

        default:
          throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`);
      }

      returnData.push({
        json: result,
        pairedItem: { item: i },
      });

    } catch (error: any) {
      if (this.continueOnFail()) {
        returnData.push({
          json: { error: error.message },
          pairedItem: { item: i },
        });
      } else {
        throw error;
      }
    }
  }

  return returnData;
}

async function executeThreatIntelligenceOperations(
  this: IExecuteFunctions,
  items: INodeExecutionData[],
): Promise<INodeExecutionData[]> {
  const returnData: INodeExecutionData[] = [];
  const operation = this.getNodeParameter('operation', 0) as string;
  const credentials = await this.getCredentials('crowdstrikefalconApi') as any;

  for (let i = 0; i < items.length; i++) {
    try {
      let result: any;
      const options: any = {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${credentials.accessToken}`,
          'Content-Type': 'application/json',
        },
        json: true,
      };

      switch (operation) {
        case 'queryReports': {
          const limit = this.getNodeParameter('limit', i) as number;
          const offset = this.getNodeParameter('offset', i) as number;
          const sort = this.getNodeParameter('sort', i) as string;
          const filter = this.getNodeParameter('filter', i) as string;

          const queryParams: string[] = [];
          if (limit) queryParams.push(`limit=${limit}`);
          if (offset) queryParams.push(`offset=${offset}`);
          if (sort) queryParams.push(`sort=${encodeURIComponent(sort)}`);
          if (filter) queryParams.push(`filter=${encodeURIComponent(filter)}`);

          const queryString = queryParams.length > 0 ? '?' + queryParams.join('&') : '';
          options.url = `${credentials.baseUrl}/intel/queries/reports/v1${queryString}`;
          result = await this.helpers.httpRequest(options) as any;
          break;
        }
        case 'getReports': {
          const ids = this.getNodeParameter('ids', i) as string;
          const idsArray = ids.split(',').map(id => id.trim());
          
          options.url = `${credentials.baseUrl}/intel/entities/reports/v1?ids=${idsArray.join('&ids=')}`;
          result = await this.helpers.httpRequest(options) as any;
          break;
        }
        case 'queryActors': {
          const limit = this.getNodeParameter('limit', i) as number;
          const offset = this.getNodeParameter('offset', i) as number;
          const sort = this.getNodeParameter('sort', i) as string;
          const filter = this.getNodeParameter('filter', i) as string;

          const queryParams: string[] = [];
          if (limit) queryParams.push(`limit=${limit}`);
          if (offset) queryParams.push(`offset=${offset}`);
          if (sort) queryParams.push(`sort=${encodeURIComponent(sort)}`);
          if (filter) queryParams.push(`filter=${encodeURIComponent(filter)}`);

          const queryString = queryParams.length > 0 ? '?' + queryParams.join('&') : '';
          options.url = `${credentials.baseUrl}/intel/queries/actors/v1${queryString}`;
          result = await this.helpers.httpRequest(options) as any;
          break;
        }
        case 'getActors': {
          const ids = this.getNodeParameter('ids', i) as string;
          const fields = this.getNodeParameter('fields', i) as string;
          const idsArray = ids.split(',').map(id => id.trim());
          
          const queryParams: string[] = [];
          queryParams.push(`ids=${idsArray.join('&ids=')}`);
          if (fields) queryParams.push(`fields=${encodeURIComponent(fields)}`);

          options.url = `${credentials.baseUrl}/intel/entities/actors/v1?${queryParams.join('&')}`;
          result = await this.helpers.httpRequest(options) as any;
          break;
        }
        default:
          throw new NodeOperationError(this.getNode(), `Unknown operation: ${operation}`);
      }

      returnData.push({
        json: result,
        pairedItem: { item: i },
      });
    } catch (error: any) {
      if (this.continueOnFail()) {
        returnData.push({
          json: { error: error.message },
          pairedItem: { item: i },
        });
      } else {
        throw error;
      }
    }
  }

  return returnData;
}
