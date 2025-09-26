#!/usr/bin/env python3
"""
Alert Processing Module

This module handles the loading and initial processing of security alerts.
It normalizes different alert formats into a standard internal structure
and calculates initial risk scores based on alert type and indicators.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class Alert:
    """Represents a normalized security alert with all necessary fields for processing"""
    alert_id: str
    source: str
    alert_type: str
    created_at: str
    asset: Dict[str, Any]
    indicators: Dict[str, List[str]]
    raw: Dict[str, Any]
    enriched_data: Optional[Dict[str, Any]] = None
    risk_score: Optional[int] = None
    mitre_techniques: Optional[List[str]] = None

class AlertProcessor:
    """Processes and enriches security alerts"""
    
    def __init__(self):
        self.processed_alerts = []
        
    def load_alert(self, alert_file: str) -> Alert:
        """Load and parse alert from JSON file"""
        try:
            with open(alert_file, 'r') as f:
                alert_data = json.load(f)
            
            alert = Alert(
                alert_id=alert_data['alert_id'],
                source=alert_data['source'],
                alert_type=alert_data['type'],
                created_at=alert_data['created_at'],
                asset=alert_data['asset'],
                indicators=alert_data['indicators'],
                raw=alert_data['raw']
            )
            
            logger.info(f"Loaded alert {alert.alert_id} from {alert.source}")
            return alert
            
        except Exception as e:
            logger.error(f"Error loading alert from {alert_file}: {e}")
            raise
    
    def validate_alert(self, alert: Alert) -> bool:
        """Validate alert structure and required fields"""
        required_fields = ['alert_id', 'source', 'alert_type', 'created_at', 'asset', 'indicators']
        
        for field in required_fields:
            if not hasattr(alert, field) or getattr(alert, field) is None:
                logger.error(f"Alert {alert.alert_id} missing required field: {field}")
                return False
        
        # Validate indicators structure
        if not isinstance(alert.indicators, dict):
            logger.error(f"Alert {alert.alert_id} indicators must be a dictionary")
            return False
        
        return True
    
    def extract_indicators(self, alert: Alert) -> Dict[str, List[str]]:
        """Extract and categorize indicators from alert - handles different formats"""
        indicators = {
            'ipv4': alert.indicators.get('ipv4', []),
            'domains': alert.indicators.get('domains', []),
            'urls': alert.indicators.get('urls', []),
            'sha256': alert.indicators.get('sha256', [])
        }
        
        # Filter out empty lists
        indicators = {k: v for k, v in indicators.items() if v}
        
        logger.info(f"Extracted {sum(len(v) for v in indicators.values())} indicators from alert {alert.alert_id}")
        return indicators
    
    def calculate_risk_score(self, alert: Alert, config: Optional[Dict[str, Any]] = None) -> int:
        """Calculate base risk score from alert type"""
        if config is None:
            base_scores = {
                'Malware': 70,
                'Phishing': 60,
                'Beaconing': 65,
                'CredentialAccess': 75,
                'C2': 80
            }
            base_score = base_scores.get(alert.alert_type, 50)
        else:
            base_risk_scores = config.get('base_risk_scores', {})
            base_score = base_risk_scores.get(alert.alert_type, 50)
        
        return min(base_score, 100)
    
    def process_alert(self, alert_file: str) -> Alert:
        """Main method to process an alert"""
        alert = self.load_alert(alert_file)
        
        if not self.validate_alert(alert):
            raise ValueError(f"Invalid alert structure: {alert.alert_id}")
        
        # Calculate risk score
        alert.risk_score = self.calculate_risk_score(alert)
        
        # Store processed alert
        self.processed_alerts.append(alert)
        
        logger.info(f"Processed alert {alert.alert_id} with risk score {alert.risk_score}")
        return alert
    

