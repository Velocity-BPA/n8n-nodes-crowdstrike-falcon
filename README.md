# n8n-nodes-crowdstrike-falcon

> **[Velocity BPA Licensing Notice]**
>
> This n8n node is licensed under the Business Source License 1.1 (BSL 1.1).
>
> Use of this node by for-profit organizations in production environments requires a commercial license from Velocity BPA.
>
> For licensing information, visit https://velobpa.com/licensing or contact licensing@velobpa.com.

This n8n community node provides integration with CrowdStrike Falcon, enabling automated endpoint security operations through 7 comprehensive resources. The node delivers full access to CrowdStrike's threat detection, incident management, host monitoring, IOC handling, vulnerability assessment, event streaming, and threat intelligence capabilities for enhanced security automation workflows.

![n8n Community Node](https://img.shields.io/badge/n8n-Community%20Node-blue)
![License](https://img.shields.io/badge/license-BSL--1.1-blue)
![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue)
![Security](https://img.shields.io/badge/Security-Endpoint%20Protection-red)
![Threat Detection](https://img.shields.io/badge/Threat-Detection-orange)
![SOC Automation](https://img.shields.io/badge/SOC-Automation-green)

## Features

- **Advanced Threat Detection** - Automate detection retrieval, status updates, and remediation workflows
- **Incident Response Management** - Streamline incident handling, assignment, and resolution tracking
- **Host Monitoring & Control** - Monitor endpoint health, apply policies, and manage host configurations
- **IOC Intelligence Operations** - Create, update, and manage indicators of compromise across your environment
- **Vulnerability Assessment** - Automate vulnerability scanning, reporting, and remediation prioritization
- **Real-time Event Streaming** - Process security events in real-time for immediate threat response
- **Threat Intelligence Integration** - Leverage CrowdStrike's threat intelligence for enhanced security posture
- **Enterprise-grade Security** - Secure API key authentication with comprehensive error handling

## Installation

### Community Nodes (Recommended)

1. Open n8n
2. Go to **Settings** → **Community Nodes**
3. Click **Install a community node**
4. Enter `n8n-nodes-crowdstrike-falcon`
5. Click **Install**

### Manual Installation

```bash
cd ~/.n8n
npm install n8n-nodes-crowdstrike-falcon
```

### Development Installation

```bash
git clone https://github.com/Velocity-BPA/n8n-nodes-crowdstrike-falcon.git
cd n8n-nodes-crowdstrike-falcon
npm install
npm run build
mkdir -p ~/.n8n/custom
ln -s $(pwd) ~/.n8n/custom/n8n-nodes-crowdstrike-falcon
n8n start
```

## Credentials Setup

| Field | Description | Required |
|-------|-------------|----------|
| API Key | CrowdStrike Falcon API key with appropriate scopes | Yes |
| Client ID | CrowdStrike API client identifier | Yes |
| Client Secret | CrowdStrike API client secret | Yes |
| Base URL | CrowdStrike cloud region endpoint (auto-detected) | No |

## Resources & Operations

### 1. Detections

| Operation | Description |
|-----------|-------------|
| Get All | Retrieve all detections with filtering options |
| Get by ID | Fetch specific detection details |
| Update Status | Change detection status (new, in_progress, true_positive, false_positive) |
| Assign | Assign detection to user or team |
| Add Comment | Add investigation notes to detection |
| Get Summary | Retrieve detection summary statistics |

### 2. Incidents

| Operation | Description |
|-----------|-------------|
| Get All | List all incidents with pagination and filters |
| Get by ID | Retrieve detailed incident information |
| Create | Create new incident from detection or manually |
| Update | Modify incident details and status |
| Assign | Assign incident to analyst or team |
| Close | Close incident with resolution details |
| Reopen | Reopen previously closed incident |
| Add Comment | Document investigation progress |

### 3. Hosts

| Operation | Description |
|-----------|-------------|
| Get All | List all managed hosts with system details |
| Get by ID | Retrieve specific host information |
| Search | Search hosts by hostname, IP, or other criteria |
| Contain | Isolate host from network (network containment) |
| Lift Containment | Remove network isolation from host |
| Hide Host | Hide host from console view |
| Unhide Host | Restore host visibility in console |
| Get Online Status | Check real-time host connectivity status |

### 4. IOCs

| Operation | Description |
|-----------|-------------|
| Get All | Retrieve all indicators of compromise |
| Get by ID | Fetch specific IOC details |
| Create | Add new IOC with metadata and severity |
| Update | Modify existing IOC properties |
| Delete | Remove IOC from watchlist |
| Search | Query IOCs by type, value, or source |
| Bulk Upload | Import multiple IOCs from file or list |
| Get Processes | Find processes associated with IOC |

### 5. Vulnerabilities

| Operation | Description |
|-----------|-------------|
| Get All | List all discovered vulnerabilities |
| Get by ID | Retrieve detailed vulnerability information |
| Get by CVE | Search vulnerabilities by CVE identifier |
| Get Affected Hosts | List hosts affected by specific vulnerability |
| Get Remediation | Retrieve remediation guidance and steps |
| Update Priority | Adjust vulnerability priority level |
| Mark Suppressed | Suppress vulnerability from active list |
| Get Statistics | Retrieve vulnerability metrics and trends |

### 6. EventStreams

| Operation | Description |
|-----------|-------------|
| Create Stream | Establish real-time event stream connection |
| Get Events | Retrieve events from stream with filtering |
| List Streams | Show all active event streams |
| Refresh Token | Update stream authentication token |
| Close Stream | Terminate event stream connection |
| Get Schema | Retrieve event data structure definitions |
| Filter Events | Apply custom filters to event stream |
| Parse Event | Extract and format event data |

### 7. ThreatIntelligence

| Operation | Description |
|-----------|-------------|
| Get Indicators | Retrieve threat intelligence indicators |
| Search Malware | Query malware database by hash or name |
| Get Actor | Retrieve threat actor information |
| Get Report | Access detailed threat intelligence reports |
| Get Rules | Retrieve YARA and other detection rules |
| Search IOCs | Query intelligence IOCs by various criteria |
| Get Tactics | Retrieve MITRE ATT&CK tactics and techniques |
| Get Campaign | Access threat campaign information |

## Usage Examples

```javascript
// Retrieve high-severity detections from last 24 hours
const detections = await crowdstrike.detections.getAll({
  filter: "severity:'High'+created_timestamp:>'2024-01-01T00:00:00Z'",
  limit: 100,
  sort: "created_timestamp.desc"
});
```

```javascript
// Contain compromised host and create incident
await crowdstrike.hosts.contain({
  ids: ["1234567890abcdef"],
  comment: "Malware detected - isolating host"
});

const incident = await crowdstrike.incidents.create({
  name: "Compromised Host - Malware Detection",
  description: "Host isolation due to malware detection",
  severity: "High",
  host_ids: ["1234567890abcdef"]
});
```

```javascript
// Add IOC and monitor for matches
const ioc = await crowdstrike.iocs.create({
  type: "sha256",
  value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  action: "detect",
  severity: "high",
  description: "Malicious file hash from incident IR-2024-001"
});
```

```javascript
// Stream real-time detections and auto-assign critical alerts
const stream = await crowdstrike.eventStreams.createStream({
  appId: "security-automation",
  eventTypes: ["DetectionSummaryEvent"]
});

const events = await crowdstrike.eventStreams.getEvents({
  appId: "security-automation",
  filter: "severity:'Critical'"
});
```

## Error Handling

| Error | Description | Solution |
|-------|-------------|----------|
| 401 Unauthorized | Invalid API credentials | Verify API key, client ID, and client secret |
| 403 Forbidden | Insufficient permissions | Check API key scopes and user permissions |
| 429 Rate Limited | API rate limit exceeded | Implement exponential backoff and retry logic |
| 404 Not Found | Resource ID doesn't exist | Verify resource ID and check if resource was deleted |
| 400 Bad Request | Invalid request parameters | Validate input parameters and format |
| 500 Internal Server Error | CrowdStrike service issue | Check CrowdStrike status page and retry later |

## Development

```bash
npm install
npm run build
npm test
npm run lint
npm run dev
```

## Author

**Velocity BPA**
- Website: [velobpa.com](https://velobpa.com)
- GitHub: [Velocity-BPA](https://github.com/Velocity-BPA)

## Licensing

This n8n community node is licensed under the **Business Source License 1.1**.

### Free Use
Permitted for personal, educational, research, and internal business use.

### Commercial Use
Use of this node within any SaaS, PaaS, hosted platform, managed service, or paid automation offering requires a commercial license.

For licensing inquiries: **licensing@velobpa.com**

See [LICENSE](LICENSE), [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md), and [LICENSING_FAQ.md](LICENSING_FAQ.md) for details.

## Contributing

Contributions are welcome! Please ensure:

1. Code follows existing style conventions
2. All tests pass (`npm test`)
3. Linting passes (`npm run lint`)
4. Documentation is updated for new features
5. Commit messages are descriptive

## Support

- **Issues**: [GitHub Issues](https://github.com/Velocity-BPA/n8n-nodes-crowdstrike-falcon/issues)
- **CrowdStrike API Documentation**: [CrowdStrike Falcon API Reference](https://falcon.crowdstrike.com/documentation)
- **Community**: [n8n Community Forum](https://community.n8n.io)