#!/usr/bin/env python3
"""
Prometheus AlertManager to ServiceNow Incident Bridge
======================================================
This application receives webhooks from Prometheus AlertManager
and creates incidents in ServiceNow.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Any
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuration from environment variables
SERVICENOW_INSTANCE = os.environ.get('SERVICENOW_INSTANCE', 'your-instance.service-now.com')
SERVICENOW_USERNAME = os.environ.get('SERVICENOW_USERNAME', '')
SERVICENOW_PASSWORD = os.environ.get('SERVICENOW_PASSWORD', '')
SERVICENOW_API_PATH = '/api/now/table/incident'
DEFAULT_CALLER_ID = os.environ.get('DEFAULT_CALLER_ID', '00dd09a0db302d9059991f8305961981')
DEFAULT_ASSIGNMENT_GROUP = os.environ.get('DEFAULT_ASSIGNMENT_GROUP', 'e8488d3bdb290c9018dfed384b9619d5')


class AlertManagerParser:
    """
    Parses AlertManager webhook payloads and transforms them
    into ServiceNow incident format.
    """
    
    @staticmethod
    def parse_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a single alert into ServiceNow incident format.
        
        Example AlertManager alert structure:
        {
            "status": "firing",
            "labels": {
                "alertname": "HighCPUUsage",
                "severity": "warning",
                "instance": "server1.example.com",
                "job": "node-exporter"
            },
            "annotations": {
                "description": "CPU usage is above 90% on server1",
                "summary": "High CPU usage detected"
            },
            "startsAt": "2023-01-31T04:00:00Z",
            "endsAt": "0001-01-01T00:00:00Z",
            "generatorURL": "http://prometheus.example.com/..."
        }
        """
        
        # Map severity to impact and urgency
        severity_mapping = {
            'critical': {'impact': '1', 'urgency': '1'},
            'warning': {'impact': '2', 'urgency': '2'},
            'info': {'impact': '3', 'urgency': '3'},
            'unknown': {'impact': '3', 'urgency': '3'}
        }
        
        severity = alert.get('labels', {}).get('severity', 'unknown').lower()
        severity_config = severity_mapping.get(severity, severity_mapping['unknown'])
        
        # Extract alert details
        labels = alert.get('labels', {})
        annotations = alert.get('annotations', {})
        
        # Build short description
        alert_name = labels.get('alertname', 'Unknown Alert')
        instance = labels.get('instance', 'Unknown Instance')
        short_description = f"[{alert_name}] {instance} - {annotations.get('summary', 'Alert triggered')}"
        
        # Build detailed description
        description_parts = [
            f"Alert: {alert_name}",
            f"Status: {alert.get('status', 'unknown')}",
            f"Instance: {instance}",
            f"Job: {labels.get('job', 'N/A')}",
            "",
            "Description:",
            annotations.get('description', 'No description provided'),
            "",
            "Labels:",
            json.dumps(labels, indent=2),
            "",
            f"Alert URL: {alert.get('generatorURL', 'N/A')}",
            f"Starts At: {alert.get('startsAt', 'N/A')}",
            f"Ends At: {alert.get('endsAt', 'N/A')}"
        ]
        description = '\n'.join(description_parts)
        
        # Parse timestamp
        starts_at = alert.get('startsAt', '')
        try:
            dt = datetime.fromisoformat(starts_at.replace('Z', '+00:00'))
            occurred_date = dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            occurred_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Build correlation ID from alert fingerprint or generate one
        correlation_id = f"PROM-{labels.get('alertname', 'UNKNOWN')}-{instance}-{starts_at[:10]}"
        
        # Create ServiceNow incident payload
        incident = {
            'impact': severity_config['impact'],
            'urgency': severity_config['urgency'],
            'short_description': short_description[:160],  # ServiceNow limit
            'description': description,
            'caller_id': DEFAULT_CALLER_ID,
            'state': '1',  # New
            'u_occurred_date': occurred_date,
            'assignment_group': DEFAULT_ASSIGNMENT_GROUP,
            'correlation_id': correlation_id[:100],  # Limit length
            'category': 'software',
            'subcategory': 'monitoring'
        }
        
        return incident


class ServiceNowClient:
    """
    Client for interacting with ServiceNow API.
    """
    
    def __init__(self):
        self.base_url = f"https://{SERVICENOW_INSTANCE}{SERVICENOW_API_PATH}"
        self.auth = (SERVICENOW_USERNAME, SERVICENOW_PASSWORD)
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    
    def create_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create an incident in ServiceNow.
        
        Returns the created incident details or error information.
        """
        try:
            logger.info(f"Creating ServiceNow incident: {incident_data.get('short_description', 'Unknown')}")
            logger.debug(f"Incident payload: {json.dumps(incident_data, indent=2)}")
            
            response = requests.post(
                self.base_url,
                auth=self.auth,
                headers=self.headers,
                json=incident_data,
                timeout=30
            )
            
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Successfully created incident: {result.get('result', {}).get('number', 'Unknown')}")
            return {
                'success': True,
                'incident_number': result.get('result', {}).get('number'),
                'sys_id': result.get('result', {}).get('sys_id'),
                'data': result
            }
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create ServiceNow incident: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'incident_data': incident_data
            }


# Initialize clients
parser = AlertManagerParser()
servicenow_client = ServiceNowClient()


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for Kubernetes/OpenShift."""
    return jsonify({'status': 'healthy', 'service': 'alertmanager-to-servicenow'}), 200


@app.route('/webhook', methods=['POST'])
def webhook():
    """
    Main webhook endpoint that receives AlertManager notifications.
    
    Example AlertManager webhook payload:
    {
        "version": "4",
        "groupKey": "{}:{alertname=\"HighCPUUsage\"}",
        "status": "firing",
        "receiver": "servicenow",
        "groupLabels": {"alertname": "HighCPUUsage"},
        "commonLabels": {...},
        "commonAnnotations": {...},
        "externalURL": "http://alertmanager.example.com",
        "alerts": [...]
    }
    """
    try:
        # Parse the incoming JSON payload
        payload = request.get_json(force=True)
        logger.info(f"Received webhook with {len(payload.get('alerts', []))} alerts")
        logger.debug(f"Full payload: {json.dumps(payload, indent=2)}")
        
        # Process each alert
        results = []
        alerts = payload.get('alerts', [])
        
        for alert in alerts:
            # Only process firing alerts (not resolved)
            if alert.get('status') != 'firing':
                logger.info(f"Skipping resolved alert: {alert.get('labels', {}).get('alertname', 'Unknown')}")
                continue
            
            # Parse alert into ServiceNow format
            incident_data = parser.parse_alert(alert)
            
            # Create incident in ServiceNow
            result = servicenow_client.create_incident(incident_data)
            results.append(result)
        
        # Return summary of processing
        successful = [r for r in results if r.get('success')]
        failed = [r for r in results if not r.get('success')]
        
        response_data = {
            'received_alerts': len(alerts),
            'processed': len(results),
            'successful': len(successful),
            'failed': len(failed),
            'incidents_created': [r.get('incident_number') for r in successful if r.get('incident_number')],
            'errors': [r.get('error') for r in failed if r.get('error')]
        }
        
        status_code = 200 if len(failed) == 0 else 207  # 207 = Multi-Status
        
        logger.info(f"Webhook processing complete: {response_data}")
        return jsonify(response_data), status_code
        
    except Exception as e:
        logger.error(f"Error processing webhook: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/test', methods=['GET'])
def test_endpoint():
    """
    Test endpoint to verify ServiceNow connectivity.
    Creates a test incident.
    """
    test_incident = {
        'impact': '3',
        'urgency': '3',
        'short_description': 'Test incident from AlertManager bridge',
        'description': 'This is a test incident created to verify ServiceNow connectivity.',
        'caller_id': DEFAULT_CALLER_ID,
        'state': '1',
        'u_occurred_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'assignment_group': DEFAULT_ASSIGNMENT_GROUP,
        'correlation_id': f'TEST-{datetime.now().strftime("%Y%m%d%H%M%S")}',
        'category': 'software'
    }
    
    result = servicenow_client.create_incident(test_incident)
    return jsonify(result), 200 if result.get('success') else 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    logger.info(f"Starting AlertManager to ServiceNow bridge on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
