"""
SOC AI Agent: A Google Cloud-Native Threat Analyst

This module implements the core SOC AI agent that provides:
- Autonomous Alert Triage
- Threat Intelligence Integration  
- Log and Event Correlation
- Incident Response Recommendations
- Natural Language Interaction
"""

import json
import logging
import re
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import os

from google.cloud import aiplatform
from google.cloud import pubsub_v1
from google.cloud import bigquery
from google.cloud import logging as cloud_logging
import vertexai
from vertexai.generative_models import GenerativeModel
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SOCAgent:
    """
    Main SOC AI Agent class that orchestrates security alert processing
    """
    
    def __init__(self, project_id: str, location: str = "us-central1"):
        self.project_id = project_id
        self.location = location
        
        # Initialize GCP clients
        vertexai.init(project=project_id, location=location)
        self.model = GenerativeModel("gemini-1.5-pro-001")
        
        self.bigquery_client = bigquery.Client(project=project_id)
        self.publisher = pubsub_v1.PublisherClient()
        self.subscriber = pubsub_v1.SubscriberClient()
        
        # Initialize modules
        self.enrichment = EnrichmentModule(project_id)
        self.analysis = AnalysisModule(self.model)
        self.notification = NotificationModule(project_id)
        self.storage = DataStorageModule(self.bigquery_client, project_id)
        
        logger.info(f"SOC Agent initialized for project: {project_id}")

    def process_security_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main processing pipeline for security alerts
        
        Args:
            alert_data: Raw security alert data
            
        Returns:
            Dict containing processed alert with analysis and recommendations
        """
        try:
            logger.info(f"Processing security alert: {alert_data.get('alert_id', 'Unknown')}")
            
            # Step 1: Extract entities and enrich alert
            enriched_alert = self.enrichment.enrich_alert(alert_data)
            
            # Step 2: Perform AI-powered analysis
            analysis_result = self.analysis.analyze_incident(enriched_alert)
            
            # Step 3: Store results in BigQuery
            incident_record = self.storage.store_incident(enriched_alert, analysis_result)
            
            # Step 4: Send notifications if severity is high
            if analysis_result.get('severity_score', 0) >= 7:
                self.notification.send_alert_notification(incident_record)
            
            logger.info(f"Successfully processed alert: {alert_data.get('alert_id', 'Unknown')}")
            
            return {
                'success': True,
                'incident_id': incident_record['incident_id'],
                'severity_score': analysis_result.get('severity_score'),
                'summary': analysis_result.get('summary'),
                'recommendations': analysis_result.get('recommendations')
            }
            
        except Exception as e:
            logger.error(f"Error processing alert: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

class EnrichmentModule:
    """
    Handles alert enrichment with threat intelligence and contextual data
    """
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.threat_intel_sources = {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'abuseipdb': os.getenv('ABUSEIPDB_API_KEY')
        }
    
    def enrich_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich security alert with additional context and threat intelligence
        """
        enriched = alert_data.copy()
        
        # Extract entities (IPs, domains, hashes, usernames)
        entities = self._extract_entities(alert_data)
        enriched['extracted_entities'] = entities
        
        # Get threat intelligence for each entity
        threat_intel = self._get_threat_intelligence(entities)
        enriched['threat_intelligence'] = threat_intel
        
        # Get historical context from logs
        historical_context = self._get_historical_context(entities)
        enriched['historical_context'] = historical_context
        
        logger.info(f"Enriched alert with {len(entities)} entities and threat intel")
        
        return enriched
    
    def _extract_entities(self, alert_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract IPs, domains, hashes, and usernames from alert data"""
        text = json.dumps(alert_data)
        
        entities = {
            'ip_addresses': self._extract_ips(text),
            'domains': self._extract_domains(text),
            'file_hashes': self._extract_hashes(text),
            'usernames': self._extract_usernames(text)
        }
        
        return entities
    
    def _extract_ips(self, text: str) -> List[str]:
        """Extract IP addresses using regex"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return list(set(re.findall(ip_pattern, text)))
    
    def _extract_domains(self, text: str) -> List[str]:
        """Extract domain names using regex"""
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, text)
        return list(set([d[0] + d[1] + d[2] for d in domains if d]))
    
    def _extract_hashes(self, text: str) -> List[str]:
        """Extract file hashes (MD5, SHA1, SHA256)"""
        hash_patterns = [
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b',  # SHA1
            r'\b[a-fA-F0-9]{64}\b'   # SHA256
        ]
        hashes = []
        for pattern in hash_patterns:
            hashes.extend(re.findall(pattern, text))
        return list(set(hashes))
    
    def _extract_usernames(self, text: str) -> List[str]:
        """Extract potential usernames"""
        username_pattern = r'\b[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        emails = re.findall(username_pattern, text)
        usernames = [email.split('@')[0] for email in emails]
        
        # Also look for user= patterns
        user_pattern = r'user[=:]\s*([a-zA-Z0-9._-]+)'
        users = re.findall(user_pattern, text, re.IGNORECASE)
        usernames.extend(users)
        
        return list(set(usernames))
    
    def _get_threat_intelligence(self, entities: Dict[str, List[str]]) -> Dict[str, Any]:
        """Get threat intelligence for extracted entities"""
        threat_intel = {}
        
        # Check IPs against threat intel sources
        for ip in entities.get('ip_addresses', []):
            threat_intel[ip] = self._check_ip_reputation(ip)
        
        # Check domains against threat intel sources
        for domain in entities.get('domains', []):
            threat_intel[domain] = self._check_domain_reputation(domain)
        
        # Check file hashes
        for file_hash in entities.get('file_hashes', []):
            threat_intel[file_hash] = self._check_hash_reputation(file_hash)
        
        return threat_intel
    
    def _check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation using AbuseIPDB and other sources"""
        reputation_data = {
            'ip': ip,
            'is_malicious': False,
            'confidence_score': 0,
            'sources': []
        }
        
        # AbuseIPDB check
        if self.threat_intel_sources.get('abuseipdb'):
            try:
                url = 'https://api.abuseipdb.com/api/v2/check'
                headers = {
                    'Key': self.threat_intel_sources['abuseipdb'],
                    'Accept': 'application/json'
                }
                params = {
                    'ipAddress': ip,
                    'maxAgeInDays': 90,
                    'verbose': ''
                }
                
                response = requests.get(url, headers=headers, params=params, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('data', {}).get('abuseConfidencePercentage', 0) > 25:
                        reputation_data['is_malicious'] = True
                        reputation_data['confidence_score'] = data['data']['abuseConfidencePercentage']
                        reputation_data['sources'].append('AbuseIPDB')
                        
            except Exception as e:
                logger.warning(f"Error checking IP reputation for {ip}: {str(e)}")
        
        return reputation_data
    
    def _check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation"""
        reputation_data = {
            'domain': domain,
            'is_malicious': False,
            'confidence_score': 0,
            'sources': []
        }
        
        # VirusTotal check
        if self.threat_intel_sources.get('virustotal'):
            try:
                url = f'https://www.virustotal.com/vtapi/v2/domain/report'
                params = {
                    'apikey': self.threat_intel_sources['virustotal'],
                    'domain': domain
                }
                
                response = requests.get(url, params=params, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('positives', 0) > 0:
                        reputation_data['is_malicious'] = True
                        reputation_data['confidence_score'] = (data['positives'] / data.get('total', 1)) * 100
                        reputation_data['sources'].append('VirusTotal')
                        
            except Exception as e:
                logger.warning(f"Error checking domain reputation for {domain}: {str(e)}")
        
        return reputation_data
    
    def _check_hash_reputation(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash reputation"""
        reputation_data = {
            'hash': file_hash,
            'is_malicious': False,
            'confidence_score': 0,
            'sources': []
        }
        
        # VirusTotal check
        if self.threat_intel_sources.get('virustotal'):
            try:
                url = f'https://www.virustotal.com/vtapi/v2/file/report'
                params = {
                    'apikey': self.threat_intel_sources['virustotal'],
                    'resource': file_hash
                }
                
                response = requests.get(url, params=params, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('positives', 0) > 0:
                        reputation_data['is_malicious'] = True
                        reputation_data['confidence_score'] = (data['positives'] / data.get('total', 1)) * 100
                        reputation_data['sources'].append('VirusTotal')
                        
            except Exception as e:
                logger.warning(f"Error checking hash reputation for {file_hash}: {str(e)}")
        
        return reputation_data
    
    def _get_historical_context(self, entities: Dict[str, List[str]]) -> Dict[str, Any]:
        """Get historical context from Chronicle or other log sources"""
        # This would integrate with Chronicle Security Operations API
        # For now, returning placeholder data
        return {
            'similar_incidents': 0,
            'entity_first_seen': datetime.now().isoformat(),
            'frequency_analysis': {}
        }

class AnalysisModule:
    """
    Handles AI-powered threat analysis using Vertex AI Gemini
    """
    
    def __init__(self, model: GenerativeModel):
        self.model = model
    
    def analyze_incident(self, enriched_alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze the enriched incident using Gemini AI
        """
        prompt = self._construct_analysis_prompt(enriched_alert)
        
        try:
            response = self.model.generate_content(prompt)
            analysis_result = self._parse_analysis_response(response.text)
            
            logger.info(f"AI analysis completed with severity score: {analysis_result.get('severity_score', 'Unknown')}")
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Error in AI analysis: {str(e)}")
            return self._get_fallback_analysis(enriched_alert)
    
    def _construct_analysis_prompt(self, alert_data: Dict[str, Any]) -> str:
        """Construct detailed prompt for Gemini analysis"""
        
        prompt = f"""
You are an expert cybersecurity analyst. Analyze the following security alert and provide a comprehensive assessment.

SECURITY ALERT DATA:
{json.dumps(alert_data, indent=2)}

Please provide your analysis in the following JSON format:

{{
    "severity_score": <integer from 1-10>,
    "threat_category": "<category of threat>",
    "summary": "<detailed summary of the incident>",
    "attack_vector": "<likely attack vector>",
    "blast_radius": "<assessment of potential impact>",
    "confidence_level": "<high/medium/low>",
    "indicators_of_compromise": ["<list of IOCs>"],
    "timeline": ["<chronological list of events>"],
    "recommendations": [
        {{
            "action": "<recommended action>",
            "priority": "<high/medium/low>",
            "rationale": "<why this action is recommended>"
        }}
    ],
    "false_positive_likelihood": <percentage>,
    "related_threats": ["<list of related threat patterns>"]
}}

Consider the following in your analysis:
1. Threat intelligence data provided
2. Historical context and patterns
3. Potential for lateral movement
4. Business impact assessment
5. Recommended containment and remediation steps

Provide actionable insights that would help a human analyst make informed decisions.
"""
        
        return prompt
    
    def _parse_analysis_response(self, response_text: str) -> Dict[str, Any]:
        """Parse the JSON response from Gemini"""
        try:
            # Extract JSON from response if it's wrapped in markdown
            if "```json" in response_text:
                start = response_text.find("```json") + 7
                end = response_text.find("```", start)
                json_str = response_text[start:end].strip()
            else:
                json_str = response_text.strip()
            
            return json.loads(json_str)
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {str(e)}")
            return self._get_fallback_analysis_simple()
    
    def _get_fallback_analysis(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Provide fallback analysis when AI fails"""
        severity = 5  # Default medium severity
        
        # Simple heuristics for severity
        if alert_data.get('threat_intelligence', {}):
            malicious_indicators = sum(1 for entity_data in alert_data['threat_intelligence'].values() 
                                     if entity_data.get('is_malicious', False))
            if malicious_indicators > 0:
                severity = min(8, 5 + malicious_indicators)
        
        return {
            'severity_score': severity,
            'threat_category': 'Unknown',
            'summary': 'Automated analysis failed. Manual review required.',
            'attack_vector': 'Unknown',
            'blast_radius': 'Unknown - requires manual assessment',
            'confidence_level': 'low',
            'indicators_of_compromise': [],
            'timeline': [],
            'recommendations': [{
                'action': 'Manual investigation required',
                'priority': 'high',
                'rationale': 'Automated analysis could not be completed'
            }],
            'false_positive_likelihood': 50,
            'related_threats': []
        }
    
    def _get_fallback_analysis_simple(self) -> Dict[str, Any]:
        """Simple fallback when parsing fails"""
        return {
            'severity_score': 5,
            'threat_category': 'Parse Error',
            'summary': 'AI response could not be parsed',
            'recommendations': []
        }

class NotificationModule:
    """
    Handles notifications to security teams
    """
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.publisher = pubsub_v1.PublisherClient()
        self.notification_topic = f"projects/{project_id}/topics/security-notifications"
        
        # Webhook URLs for different notification channels
        self.webhook_urls = {
            'slack': os.getenv('SLACK_WEBHOOK_URL'),
            'teams': os.getenv('TEAMS_WEBHOOK_URL'),
            'email': os.getenv('EMAIL_WEBHOOK_URL')
        }
    
    def send_alert_notification(self, incident_data: Dict[str, Any]):
        """Send notification for high-severity incidents"""
        try:
            # Create notification message
            notification = self._create_notification_message(incident_data)
            
            # Publish to Pub/Sub topic
            self._publish_to_pubsub(notification)
            
            # Send to external channels
            self._send_to_external_channels(notification)
            
            logger.info(f"Notification sent for incident: {incident_data.get('incident_id')}")
            
        except Exception as e:
            logger.error(f"Error sending notification: {str(e)}")
    
    def _create_notification_message(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create structured notification message"""
        analysis = incident_data.get('analysis_result', {})
        
        return {
            'incident_id': incident_data['incident_id'],
            'timestamp': datetime.now().isoformat(),
            'severity_score': analysis.get('severity_score', 0),
            'threat_category': analysis.get('threat_category', 'Unknown'),
            'summary': analysis.get('summary', 'No summary available'),
            'recommendations': analysis.get('recommendations', []),
            'indicators_of_compromise': analysis.get('indicators_of_compromise', []),
            'dashboard_url': f"https://console.cloud.google.com/bigquery?project={self.project_id}"
        }
    
    def _publish_to_pubsub(self, notification: Dict[str, Any]):
        """Publish notification to Pub/Sub topic"""
        try:
            message_data = json.dumps(notification).encode('utf-8')
            future = self.publisher.publish(self.notification_topic, message_data)
            future.result()  # Wait for publish to complete
            
        except Exception as e:
            logger.error(f"Error publishing to Pub/Sub: {str(e)}")
    
    def _send_to_external_channels(self, notification: Dict[str, Any]):
        """Send notifications to external channels like Slack"""
        
        # Slack notification
        if self.webhook_urls.get('slack'):
            slack_message = self._format_slack_message(notification)
            self._send_webhook(self.webhook_urls['slack'], slack_message)
        
        # Teams notification
        if self.webhook_urls.get('teams'):
            teams_message = self._format_teams_message(notification)
            self._send_webhook(self.webhook_urls['teams'], teams_message)
    
    def _format_slack_message(self, notification: Dict[str, Any]) -> Dict[str, Any]:
        """Format message for Slack"""
        severity_emoji = "🚨" if notification['severity_score'] >= 8 else "⚠️"
        
        return {
            "text": f"{severity_emoji} Security Alert - Severity {notification['severity_score']}/10",
            "attachments": [
                {
                    "color": "danger" if notification['severity_score'] >= 7 else "warning",
                    "fields": [
                        {
                            "title": "Incident ID",
                            "value": notification['incident_id'],
                            "short": True
                        },
                        {
                            "title": "Threat Category",
                            "value": notification['threat_category'],
                            "short": True
                        },
                        {
                            "title": "Summary",
                            "value": notification['summary'][:500] + ("..." if len(notification['summary']) > 500 else ""),
                            "short": False
                        }
                    ],
                    "actions": [
                        {
                            "type": "button",
                            "text": "View in Dashboard",
                            "url": notification['dashboard_url']
                        }
                    ]
                }
            ]
        }
    
    def _format_teams_message(self, notification: Dict[str, Any]) -> Dict[str, Any]:
        """Format message for Microsoft Teams"""
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": f"Security Alert - Severity {notification['severity_score']}/10",
            "themeColor": "FF0000" if notification['severity_score'] >= 7 else "FFA500",
            "sections": [
                {
                    "activityTitle": f"Security Incident {notification['incident_id']}",
                    "activitySubtitle": f"Severity: {notification['severity_score']}/10",
                    "facts": [
                        {
                            "name": "Threat Category",
                            "value": notification['threat_category']
                        },
                        {
                            "name": "Summary",
                            "value": notification['summary'][:500]
                        }
                    ]
                }
            ],
            "potentialAction": [
                {
                    "@type": "OpenUri",
                    "name": "View Dashboard",
                    "targets": [
                        {
                            "os": "default",
                            "uri": notification['dashboard_url']
                        }
                    ]
                }
            ]
        }
    
    def _send_webhook(self, webhook_url: str, message: Dict[str, Any]):
        """Send webhook notification"""
        try:
            response = requests.post(
                webhook_url,
                json=message,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            response.raise_for_status()
            
        except Exception as e:
            logger.error(f"Error sending webhook notification: {str(e)}")

class DataStorageModule:
    """
    Handles data storage in BigQuery
    """
    
    def __init__(self, bigquery_client: bigquery.Client, project_id: str):
        self.client = bigquery_client
        self.project_id = project_id
        self.dataset_id = "soc_agent_data"
        self.table_id = "security_incidents"
        
        self._ensure_dataset_exists()
        self._ensure_table_exists()
    
    def store_incident(self, enriched_alert: Dict[str, Any], analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Store incident data in BigQuery"""
        
        incident_record = {
            'incident_id': self._generate_incident_id(),
            'timestamp': datetime.now().isoformat(),
            'original_alert': json.dumps(enriched_alert),
            'analysis_result': json.dumps(analysis_result),
            'severity_score': analysis_result.get('severity_score', 0),
            'threat_category': analysis_result.get('threat_category', 'Unknown'),
            'false_positive_likelihood': analysis_result.get('false_positive_likelihood', 0),
            'processed_at': datetime.now().isoformat()
        }
        
        try:
            table_ref = self.client.dataset(self.dataset_id).table(self.table_id)
            table = self.client.get_table(table_ref)
            
            rows_to_insert = [incident_record]
            errors = self.client.insert_rows_json(table, rows_to_insert)
            
            if errors:
                logger.error(f"Error inserting incident data: {errors}")
            else:
                logger.info(f"Incident stored successfully: {incident_record['incident_id']}")
            
            return incident_record
            
        except Exception as e:
            logger.error(f"Error storing incident in BigQuery: {str(e)}")
            return incident_record
    
    def _generate_incident_id(self) -> str:
        """Generate unique incident ID"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"SOC_{timestamp}_{hash(str(datetime.now())) % 10000:04d}"
    
    def _ensure_dataset_exists(self):
        """Ensure BigQuery dataset exists"""
        try:
            dataset_ref = self.client.dataset(self.dataset_id)
            self.client.get_dataset(dataset_ref)
            
        except Exception:
            # Dataset doesn't exist, create it
            dataset = bigquery.Dataset(dataset_ref)
            dataset.location = "US"
            dataset.description = "SOC Agent incident data"
            
            self.client.create_dataset(dataset)
            logger.info(f"Created dataset: {self.dataset_id}")
    
    def _ensure_table_exists(self):
        """Ensure BigQuery table exists with proper schema"""
        try:
            table_ref = self.client.dataset(self.dataset_id).table(self.table_id)
            self.client.get_table(table_ref)
            
        except Exception:
            # Table doesn't exist, create it
            schema = [
                bigquery.SchemaField("incident_id", "STRING", mode="REQUIRED"),
                bigquery.SchemaField("timestamp", "TIMESTAMP", mode="REQUIRED"),
                bigquery.SchemaField("original_alert", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("analysis_result", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("severity_score", "INTEGER", mode="NULLABLE"),
                bigquery.SchemaField("threat_category", "STRING", mode="NULLABLE"),
                bigquery.SchemaField("false_positive_likelihood", "FLOAT", mode="NULLABLE"),
                bigquery.SchemaField("processed_at", "TIMESTAMP", mode="REQUIRED"),
            ]
            
            table = bigquery.Table(table_ref, schema=schema)
            table.description = "Security incidents processed by SOC Agent"
            
            self.client.create_table(table)
            logger.info(f"Created table: {self.table_id}")

def main():
    """
    Main function for testing the SOC Agent
    """
    project_id = os.getenv('GOOGLE_CLOUD_PROJECT')
    if not project_id:
        logger.error("GOOGLE_CLOUD_PROJECT environment variable not set")
        return
    
    # Initialize SOC Agent
    agent = SOCAgent(project_id)
    
    # Sample alert for testing
    sample_alert = {
        'alert_id': 'TEST_001',
        'timestamp': datetime.now().isoformat(),
        'source': 'Test System',
        'description': 'Suspicious network activity detected from IP 192.168.1.100',
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.5',
        'user': 'test_user',
        'severity': 'high'
    }
    
    # Process the alert
    result = agent.process_security_alert(sample_alert)
    
    logger.info(f"Processing result: {json.dumps(result, indent=2)}")

if __name__ == "__main__":
    main()
