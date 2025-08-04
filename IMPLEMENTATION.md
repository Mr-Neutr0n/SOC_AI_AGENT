# SOC AI Agent - Implementation Guide

## 🚀 Overview

This repository contains a fully functional SOC (Security Operations Center) AI Agent built on Google Cloud Platform. The agent provides autonomous alert triage, threat intelligence integration, AI-powered analysis, and automated incident response recommendations.

## 📁 Project Structure

```
SOC_AI_AGENT/
├── soc_agent/
│   └── agent.py              # Core SOC agent implementation
├── main.py                   # Cloud Function entry points
├── requirements.txt          # Python dependencies
├── config.yaml              # Configuration settings
├── env.example              # Environment variables template
├── deploy.sh                # Automated deployment script
├── test_agent.py           # Testing utility
├── README.md               # Original specifications
└── IMPLEMENTATION.md       # This implementation guide
```

## 🏗️ Architecture Implementation

The implemented architecture follows the modular, event-driven design specified in the README:

### Core Components

1. **SOCAgent** - Main orchestrator class
2. **EnrichmentModule** - Threat intelligence and entity extraction
3. **AnalysisModule** - AI-powered threat analysis using Gemini
4. **NotificationModule** - Multi-channel alerting system
5. **DataStorageModule** - BigQuery data persistence

### Data Flow

```
Security Alert → Pub/Sub → Cloud Function → SOC Agent → Analysis → Storage → Notifications
```

## 🔧 Implementation Features

### ✅ Completed Features

#### 1. Autonomous Alert Triage
- **Entity Extraction**: Automatic extraction of IPs, domains, file hashes, and usernames
- **Pattern Matching**: Advanced regex patterns for security indicators
- **Data Validation**: Input validation and sanitization

#### 2. Threat Intelligence Integration
- **VirusTotal API**: Domain and file hash reputation checking
- **AbuseIPDB API**: IP reputation and abuse confidence scoring
- **Extensible Framework**: Easy addition of new threat intel sources
- **Rate Limiting**: Built-in API rate limiting and error handling

#### 3. AI-Powered Analysis
- **Gemini Integration**: Uses Vertex AI Gemini 1.5 Pro for analysis
- **Structured Prompting**: Comprehensive analysis prompts with JSON output
- **Fallback Analysis**: Heuristic-based fallback when AI is unavailable
- **Severity Scoring**: 1-10 severity scale with confidence levels

#### 4. Data Storage and Persistence
- **BigQuery Integration**: Automatic dataset and table creation
- **Schema Management**: Proper schema definition for incident data
- **Data Retention**: Configurable retention and archival policies
- **Query Optimization**: Partitioned tables for efficient querying

#### 5. Multi-Channel Notifications
- **Slack Integration**: Rich message formatting with attachments
- **Microsoft Teams**: Adaptive card formatting
- **Pub/Sub Publishing**: Internal notification system
- **Severity-Based Routing**: Configurable severity thresholds

#### 6. Cloud Function Deployment
- **Pub/Sub Trigger**: Event-driven processing
- **HTTP Endpoints**: Manual testing and API access
- **Error Handling**: Comprehensive error handling and logging
- **Health Checks**: Built-in health monitoring

#### 7. Testing Framework
- **Unit Testing**: Local agent testing capabilities
- **Integration Testing**: End-to-end testing with real GCP services
- **Test Scenarios**: Pre-built test cases for different attack types
- **Test Reporting**: Automated test report generation

## 🛠️ Configuration

### Environment Variables

```bash
# Required
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# Threat Intelligence (Optional but recommended)
VIRUSTOTAL_API_KEY=your-virustotal-key
ABUSEIPDB_API_KEY=your-abuseipdb-key

# Notifications (Optional)
SLACK_WEBHOOK_URL=your-slack-webhook
TEAMS_WEBHOOK_URL=your-teams-webhook
```

### Configuration File (config.yaml)

The agent supports comprehensive configuration including:
- GCP service settings
- AI model parameters
- Threat intelligence sources
- Notification channels
- Performance tuning
- Security settings

## 🚀 Deployment

### Prerequisites

1. **Google Cloud Project** with billing enabled
2. **Required APIs** enabled (automated by deployment script)
3. **Service Account** with appropriate permissions
4. **gcloud CLI** installed and authenticated

### Quick Deployment

```bash
# Set your project ID
export GOOGLE_CLOUD_PROJECT=your-project-id

# Make deployment script executable
chmod +x deploy.sh

# Run deployment
./deploy.sh
```

### Manual Deployment Steps

1. **Enable APIs**:
   ```bash
   gcloud services enable cloudfunctions.googleapis.com
   gcloud services enable pubsub.googleapis.com
   gcloud services enable bigquery.googleapis.com
   gcloud services enable aiplatform.googleapis.com
   ```

2. **Create Service Account**:
   ```bash
   gcloud iam service-accounts create soc-agent-sa \
     --display-name="SOC AI Agent Service Account"
   ```

3. **Deploy Function**:
   ```bash
   gcloud functions deploy soc-ai-agent \
     --runtime=python311 \
     --trigger-topic=security-alerts \
     --entry-point=process_security_alert \
     --source=.
   ```

## 🧪 Testing

### Local Testing

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export GOOGLE_CLOUD_PROJECT=your-project-id

# Run local tests
python test_agent.py --project-id your-project-id --local-only
```

### Cloud Testing

```bash
# Test with Pub/Sub
python test_agent.py --project-id your-project-id --test-type network

# Test HTTP endpoint
python test_agent.py --project-id your-project-id \
  --endpoint-url https://your-function-url \
  --test-type malware

# Comprehensive test suite
python test_agent.py --project-id your-project-id \
  --endpoint-url https://your-function-url \
  --output-file test-report.txt
```

### Test Scenarios

The testing framework includes pre-built scenarios for:
- **Network Intrusion**: Suspicious IP activity
- **Malware Detection**: File-based threats
- **Authentication Failures**: Brute force attempts
- **Data Exfiltration**: Unusual data transfers

## 📊 Monitoring and Logging

### Cloud Logging

All agent activities are logged to Google Cloud Logging with structured logs:

```bash
# View function logs
gcloud functions logs read soc-ai-agent --region=us-central1

# View specific incident
gcloud logging read "resource.type=cloud_function AND 
  jsonPayload.incident_id=SOC_20240101_120000_1234"
```

### BigQuery Analytics

Query incident data for analysis:

```sql
SELECT 
  incident_id,
  severity_score,
  threat_category,
  TIMESTAMP(timestamp) as incident_time,
  JSON_EXTRACT_SCALAR(analysis_result, '$.summary') as summary
FROM `your-project.soc_agent_data.security_incidents`
WHERE DATE(timestamp) = CURRENT_DATE()
ORDER BY severity_score DESC;
```

## 🔒 Security Considerations

### Implemented Security Features

1. **Data Encryption**: All data encrypted in transit and at rest
2. **Service Account Permissions**: Minimal required permissions
3. **API Key Management**: Secure environment variable handling
4. **Input Validation**: Comprehensive input sanitization
5. **Audit Logging**: Full audit trail of all operations

### Best Practices

1. **Rotate API Keys** regularly
2. **Monitor Function Logs** for anomalies
3. **Update Dependencies** regularly
4. **Review IAM Permissions** periodically
5. **Enable VPC Service Controls** for additional security

## 📈 Performance Optimization

### Current Optimizations

- **Concurrent Processing**: Supports multiple simultaneous alerts
- **Caching**: Threat intelligence result caching
- **Batching**: Optimized BigQuery inserts
- **Resource Allocation**: Appropriate memory and timeout settings

### Scaling Considerations

- **Function Concurrency**: Adjust based on alert volume
- **BigQuery Slots**: Scale for high-volume analytics
- **Pub/Sub Subscriptions**: Multiple subscribers for load distribution

## 🛣️ Roadmap and Extensions

### Phase 1 Enhancements (Ready for Implementation)

1. **Chronicle Integration**: Real historical context from Chronicle
2. **Custom ML Models**: Anomaly detection models
3. **Advanced Correlation**: Cross-incident pattern analysis
4. **Automated Response**: Basic containment actions

### Phase 2 Features

1. **Web UI Dashboard**: Analyst interface
2. **Workflow Automation**: SOAR integration
3. **Threat Hunting**: Proactive threat discovery
4. **Compliance Reporting**: Automated compliance reports

## 💡 Usage Examples

### Publishing Test Alert

```python
import json
from google.cloud import pubsub_v1

publisher = pubsub_v1.PublisherClient()
topic_path = publisher.topic_path('your-project', 'security-alerts')

alert = {
    'alert_id': 'TEST_001',
    'timestamp': '2024-01-01T12:00:00Z',
    'description': 'Suspicious network activity',
    'src_ip': '192.168.1.100',
    'severity': 'high'
}

future = publisher.publish(topic_path, json.dumps(alert).encode())
print(f"Published message: {future.result()}")
```

### Querying Incidents

```python
from google.cloud import bigquery

client = bigquery.Client()
query = """
    SELECT incident_id, severity_score, threat_category
    FROM `your-project.soc_agent_data.security_incidents`
    WHERE severity_score >= 7
    ORDER BY timestamp DESC
    LIMIT 10
"""

results = client.query(query)
for row in results:
    print(f"Incident: {row.incident_id}, Severity: {row.severity_score}")
```

## 🆘 Troubleshooting

### Common Issues

1. **Permission Errors**: Ensure service account has required roles
2. **API Quota Exceeded**: Check Vertex AI and threat intel quotas
3. **Function Timeout**: Increase timeout for complex analysis
4. **BigQuery Errors**: Verify dataset exists and permissions

### Debug Mode

Enable debug logging:

```bash
# Set environment variable
export DEBUG_MODE=true

# View detailed logs
gcloud functions logs read soc-ai-agent --region=us-central1 --limit=50
```

## 📞 Support and Contribution

### Getting Help

1. Check the troubleshooting section
2. Review Cloud Function logs
3. Validate configuration settings
4. Test with simple alert scenarios

### Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Submit pull request with documentation

---

## ✅ Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| Core Agent | ✅ Complete | Full implementation with all modules |
| Threat Intel | ✅ Complete | VirusTotal & AbuseIPDB integration |
| AI Analysis | ✅ Complete | Gemini integration with fallback |
| Data Storage | ✅ Complete | BigQuery with auto-schema |
| Notifications | ✅ Complete | Slack, Teams, Pub/Sub |
| Cloud Functions | ✅ Complete | Both Pub/Sub and HTTP triggers |
| Testing Framework | ✅ Complete | Comprehensive test suite |
| Deployment | ✅ Complete | Automated deployment script |
| Documentation | ✅ Complete | Full implementation guide |

The SOC AI Agent is **production-ready** and can be deployed immediately to start processing security alerts with AI-powered analysis and automated response recommendations. 