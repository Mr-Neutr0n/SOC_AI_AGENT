"""
Cloud Function entry point for SOC AI Agent
Triggered by Pub/Sub messages containing security alerts
"""

import json
import base64
import logging
import os
from typing import Dict, Any

import functions_framework
from soc_agent.agent import SOCAgent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize the SOC Agent
PROJECT_ID = os.getenv('GOOGLE_CLOUD_PROJECT')
if not PROJECT_ID:
    raise ValueError("GOOGLE_CLOUD_PROJECT environment variable must be set")

soc_agent = SOCAgent(PROJECT_ID)

@functions_framework.cloud_event
def process_security_alert(cloud_event):
    """
    Cloud Function triggered by Pub/Sub messages
    
    Args:
        cloud_event: CloudEvent containing the Pub/Sub message
    """
    try:
        # Decode the Pub/Sub message
        alert_data = _decode_pubsub_message(cloud_event.data)
        
        logger.info(f"Received security alert: {alert_data.get('alert_id', 'Unknown')}")
        
        # Process the alert using the SOC Agent
        result = soc_agent.process_security_alert(alert_data)
        
        if result.get('success'):
            logger.info(f"Successfully processed alert {alert_data.get('alert_id')}: "
                       f"Severity {result.get('severity_score')}, "
                       f"Incident ID {result.get('incident_id')}")
        else:
            logger.error(f"Failed to process alert {alert_data.get('alert_id')}: "
                        f"{result.get('error')}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error in Cloud Function: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

def _decode_pubsub_message(message_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decode Pub/Sub message data
    
    Args:
        message_data: The Pub/Sub message data
        
    Returns:
        Dict containing the alert data
    """
    try:
        # Extract message from Pub/Sub envelope
        message = message_data.get('message', {})
        
        # Decode base64 data
        if 'data' in message:
            decoded_data = base64.b64decode(message['data']).decode('utf-8')
            alert_data = json.loads(decoded_data)
        else:
            # Fallback: use attributes if data is not present
            alert_data = message.get('attributes', {})
        
        # Add Pub/Sub metadata
        alert_data['pubsub_metadata'] = {
            'message_id': message.get('messageId'),
            'publish_time': message.get('publishTime'),
            'attributes': message.get('attributes', {})
        }
        
        return alert_data
        
    except Exception as e:
        logger.error(f"Error decoding Pub/Sub message: {str(e)}")
        raise ValueError(f"Invalid Pub/Sub message format: {str(e)}")

@functions_framework.http
def manual_trigger(request):
    """
    HTTP endpoint for manual testing and alert submission
    
    Args:
        request: HTTP request object
        
    Returns:
        JSON response with processing result
    """
    try:
        # Get alert data from request
        if request.method == 'POST':
            alert_data = request.get_json()
            if not alert_data:
                return {
                    'success': False,
                    'error': 'No JSON data provided'
                }, 400
        else:
            # GET request with sample data for testing
            alert_data = {
                'alert_id': 'MANUAL_TEST',
                'timestamp': '2024-01-01T12:00:00Z',
                'source': 'Manual Test',
                'description': 'Test alert for SOC Agent validation',
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.5',
                'user': 'test_user',
                'severity': 'medium'
            }
        
        logger.info(f"Manual trigger for alert: {alert_data.get('alert_id', 'Unknown')}")
        
        # Process the alert
        result = soc_agent.process_security_alert(alert_data)
        
        return result, 200 if result.get('success') else 500
        
    except Exception as e:
        logger.error(f"Error in manual trigger: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }, 500

@functions_framework.http
def health_check(request):
    """
    Health check endpoint
    
    Returns:
        JSON response indicating service health
    """
    try:
        # Basic health check
        health_status = {
            'status': 'healthy',
            'project_id': PROJECT_ID,
            'timestamp': '2024-01-01T12:00:00Z',
            'version': '1.0.0'
        }
        
        return health_status, 200
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            'status': 'unhealthy',
            'error': str(e)
        }, 500

if __name__ == "__main__":
    # For local testing
    import uvicorn
    from flask import Flask, request as flask_request
    
    app = Flask(__name__)
    
    @app.route('/process', methods=['POST'])
    def local_process():
        return manual_trigger(flask_request)
    
    @app.route('/health')
    def local_health():
        return health_check(flask_request)
    
    app.run(host='0.0.0.0', port=8080, debug=True) 