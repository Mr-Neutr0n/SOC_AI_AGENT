#!/usr/bin/env python3
"""
SOC AI Agent Testing Utility

This script provides various testing scenarios for the SOC AI Agent
including local testing, Pub/Sub message publishing, and validation.
"""

import json
import base64
import logging
import os
import sys
import argparse
from datetime import datetime
from typing import Dict, Any, List

from google.cloud import pubsub_v1
import requests

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SOCAgentTester:
    """Testing utility for SOC AI Agent"""
    
    def __init__(self, project_id: str, region: str = "us-central1"):
        self.project_id = project_id
        self.region = region
        self.publisher = pubsub_v1.PublisherClient()
        self.topic_path = self.publisher.topic_path(project_id, "security-alerts")
        
    def create_test_alert(self, alert_type: str = "network") -> Dict[str, Any]:
        """Create a test security alert"""
        
        base_alert = {
            'alert_id': f'TEST_{alert_type.upper()}_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
            'timestamp': datetime.now().isoformat(),
            'source': 'SOC Agent Test Suite',
            'alert_type': alert_type,
            'severity': 'high'
        }
        
        if alert_type == "network":
            return {
                **base_alert,
                'description': 'Suspicious network activity detected from known malicious IP',
                'src_ip': '185.220.101.32',  # Known Tor exit node
                'dst_ip': '10.0.0.5',
                'dst_port': 443,
                'protocol': 'TCP',
                'bytes_transferred': 1024000,
                'connection_count': 50,
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'geo_location': 'Netherlands'
            }
        
        elif alert_type == "malware":
            return {
                **base_alert,
                'description': 'Malicious file detected during email scan',
                'file_name': 'invoice_2024.exe',
                'file_hash': '5d41402abc4b2a76b9719d911017c592',  # MD5 of "hello"
                'file_size': 2048,
                'email_sender': 'noreply@suspicious-domain.com',
                'email_subject': 'Urgent: Invoice Payment Required',
                'detection_engine': 'ClamAV',
                'quarantine_status': 'quarantined'
            }
        
        elif alert_type == "authentication":
            return {
                **base_alert,
                'description': 'Multiple failed login attempts detected',
                'user': 'admin',
                'src_ip': '192.168.1.100',
                'failed_attempts': 15,
                'time_window': '5 minutes',
                'service': 'SSH',
                'account_status': 'active',
                'last_successful_login': '2024-01-01T08:00:00Z'
            }
        
        elif alert_type == "data_exfiltration":
            return {
                **base_alert,
                'description': 'Unusual data transfer volume detected',
                'user': 'john.doe',
                'src_ip': '10.0.0.15',
                'dst_ip': '203.0.113.10',
                'data_volume': '10GB',
                'transfer_method': 'SFTP',
                'file_types': ['xlsx', 'pdf', 'docx'],
                'classification': 'confidential',
                'business_hours': False
            }
        
        else:
            return {
                **base_alert,
                'description': f'Generic security alert of type {alert_type}',
                'details': {'custom_field': 'test_value'}
            }
    
    def test_local_agent(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Test the agent locally"""
        try:
            # Import the agent for local testing
            sys.path.append(os.path.join(os.path.dirname(__file__), 'soc_agent'))
            from soc_agent.agent import SOCAgent
            
            # Initialize agent
            agent = SOCAgent(self.project_id)
            
            # Process the alert
            result = agent.process_security_alert(alert_data)
            
            logger.info(f"Local test result: {json.dumps(result, indent=2)}")
            return result
            
        except Exception as e:
            logger.error(f"Local test failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def publish_test_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Publish test alert to Pub/Sub"""
        try:
            # Convert alert to JSON and encode
            message_data = json.dumps(alert_data).encode('utf-8')
            
            # Publish message
            future = self.publisher.publish(self.topic_path, message_data)
            message_id = future.result()
            
            logger.info(f"Published alert {alert_data['alert_id']} with message ID: {message_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to publish alert: {str(e)}")
            return False
    
    def test_http_endpoint(self, endpoint_url: str, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Test the HTTP endpoint"""
        try:
            response = requests.post(
                endpoint_url,
                json=alert_data,
                headers={'Content-Type': 'application/json'},
                timeout=60
            )
            
            response.raise_for_status()
            result = response.json()
            
            logger.info(f"HTTP test result: {json.dumps(result, indent=2)}")
            return result
            
        except Exception as e:
            logger.error(f"HTTP test failed: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def run_comprehensive_test_suite(self, endpoint_url: str = None) -> Dict[str, Any]:
        """Run comprehensive test suite"""
        results = {
            'test_suite': 'SOC Agent Comprehensive Test',
            'timestamp': datetime.now().isoformat(),
            'tests': {}
        }
        
        # Test scenarios
        test_scenarios = [
            ('network', 'Network Intrusion Test'),
            ('malware', 'Malware Detection Test'),
            ('authentication', 'Authentication Failure Test'),
            ('data_exfiltration', 'Data Exfiltration Test')
        ]
        
        for alert_type, test_name in test_scenarios:
            logger.info(f"Running {test_name}...")
            
            # Create test alert
            alert_data = self.create_test_alert(alert_type)
            
            test_result = {
                'alert_data': alert_data,
                'pubsub_test': None,
                'http_test': None,
                'local_test': None
            }
            
            # Test Pub/Sub publishing
            logger.info(f"Testing Pub/Sub for {test_name}...")
            test_result['pubsub_test'] = self.publish_test_alert(alert_data)
            
            # Test HTTP endpoint if provided
            if endpoint_url:
                logger.info(f"Testing HTTP endpoint for {test_name}...")
                test_result['http_test'] = self.test_http_endpoint(endpoint_url, alert_data)
            
            # Test local agent if possible
            try:
                logger.info(f"Testing local agent for {test_name}...")
                test_result['local_test'] = self.test_local_agent(alert_data)
            except Exception as e:
                logger.warning(f"Local test skipped for {test_name}: {str(e)}")
            
            results['tests'][alert_type] = test_result
        
        return results
    
    def generate_test_report(self, test_results: Dict[str, Any]) -> str:
        """Generate a formatted test report"""
        report = []
        report.append("=" * 60)
        report.append("SOC AI AGENT TEST REPORT")
        report.append("=" * 60)
        report.append(f"Test Suite: {test_results['test_suite']}")
        report.append(f"Timestamp: {test_results['timestamp']}")
        report.append("")
        
        for test_type, test_data in test_results['tests'].items():
            report.append(f"Test: {test_type.upper()}")
            report.append("-" * 40)
            
            # Pub/Sub test result
            pubsub_status = "PASS" if test_data['pubsub_test'] else "FAIL"
            report.append(f"Pub/Sub Publishing: {pubsub_status}")
            
            # HTTP test result
            if test_data['http_test']:
                http_status = "PASS" if test_data['http_test'].get('success') else "FAIL"
                report.append(f"HTTP Endpoint: {http_status}")
            
            # Local test result
            if test_data['local_test']:
                local_status = "PASS" if test_data['local_test'].get('success') else "FAIL"
                report.append(f"Local Agent: {local_status}")
                
                if test_data['local_test'].get('severity_score'):
                    report.append(f"Severity Score: {test_data['local_test']['severity_score']}")
            
            report.append("")
        
        return "\n".join(report)

def main():
    """Main testing function"""
    parser = argparse.ArgumentParser(description='SOC AI Agent Testing Utility')
    parser.add_argument('--project-id', required=True, help='Google Cloud Project ID')
    parser.add_argument('--region', default='us-central1', help='GCP Region')
    parser.add_argument('--endpoint-url', help='HTTP endpoint URL for testing')
    parser.add_argument('--test-type', choices=['network', 'malware', 'authentication', 'data_exfiltration', 'all'], 
                       default='all', help='Type of test to run')
    parser.add_argument('--output-file', help='Save test report to file')
    parser.add_argument('--local-only', action='store_true', help='Run only local tests')
    
    args = parser.parse_args()
    
    # Initialize tester
    tester = SOCAgentTester(args.project_id, args.region)
    
    if args.test_type == 'all':
        # Run comprehensive test suite
        logger.info("Running comprehensive test suite...")
        
        if args.local_only:
            # Run only local tests
            results = {'tests': {}}
            test_types = ['network', 'malware', 'authentication', 'data_exfiltration']
            
            for test_type in test_types:
                alert_data = tester.create_test_alert(test_type)
                result = tester.test_local_agent(alert_data)
                results['tests'][test_type] = {'local_test': result, 'alert_data': alert_data}
        else:
            results = tester.run_comprehensive_test_suite(args.endpoint_url)
        
        # Generate report
        report = tester.generate_test_report(results)
        
        print(report)
        
        # Save report if requested
        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(report)
            logger.info(f"Test report saved to {args.output_file}")
    
    else:
        # Run single test
        logger.info(f"Running {args.test_type} test...")
        
        alert_data = tester.create_test_alert(args.test_type)
        
        if args.local_only:
            result = tester.test_local_agent(alert_data)
        else:
            # Publish to Pub/Sub
            tester.publish_test_alert(alert_data)
            
            # Test HTTP endpoint if provided
            if args.endpoint_url:
                result = tester.test_http_endpoint(args.endpoint_url, alert_data)
            else:
                logger.info("Alert published to Pub/Sub. Check Cloud Function logs for results.")

if __name__ == "__main__":
    main() 