#!/usr/bin/env python3
"""
Incident Generator Module
Generates incident JSON files with complete structure
"""

import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
import threading

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global incident counter
_incident_counter = 0
_counter_lock = threading.Lock()

def get_next_incident_number() -> int:
    """Get the next sequential incident number"""
    global _incident_counter
    with _counter_lock:
        if _incident_counter == 0:
            # Initialize counter from existing files
            _incident_counter = _get_max_incident_number()
        _incident_counter += 1
        return _incident_counter

def _get_max_incident_number() -> int:
    """Get the highest incident number from existing files"""
    incidents_dir = "out/incidents"
    if not os.path.exists(incidents_dir):
        return 0
    
    max_num = 0
    for filename in os.listdir(incidents_dir):
        if filename.startswith("inc-") and filename.endswith(".json"):
            try:
                # Extract number from filename like "inc-001.json"
                num_str = filename[4:-5]  # Remove "inc-" and ".json"
                num = int(num_str)
                max_num = max(max_num, num)
            except ValueError:
                continue
    return max_num

@dataclass
class Indicator:
    """Represents an indicator in the incident"""
    type: str
    value: str
    allowlisted: bool
    hostname: Optional[str] = None
    ip: Optional[str] = None
    risk: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TimelineEntry:
    """Represents a timeline entry"""
    stage: str  # ingest|enrich|triage|respond
    bucket: str  # Low|Medium|High|Critical|Suppressed
    tags: List[str]
    result: str
    ts: str
    details: str

@dataclass
class Action:
    """Represents an action taken"""
    type: str
    target: str
    timeline: List[TimelineEntry]

@dataclass
class IncidentData:
    """Complete incident data structure"""
    incident_id: str
    source_alert: Dict[str, Any]
    asset: Dict[str, Any]
    indicators: List[Indicator]
    triage: Dict[str, Any]
    mitre: Dict[str, List[str]]
    actions: List[Action]

class IncidentGenerator:
    """Generates incident JSON files with complete structure"""
    
    def __init__(self, output_dir: str = "out"):
        self.output_dir = output_dir
        self.incidents_dir = os.path.join(output_dir, "incidents")
        self._ensure_output_directories()
    
    def _ensure_output_directories(self):
        """Create necessary output directories"""
        os.makedirs(self.incidents_dir, exist_ok=True)
        logger.info(f"Created incidents directory: {self.incidents_dir}")
    
    def _create_indicators(self, soar_result: Dict[str, Any], 
                          allowlist_check: Dict[str, Any]) -> List[Indicator]:
        """Create indicators list from SOAR result with all required fields"""
        indicators = []
        
        # Get asset information
        asset = soar_result.get('asset', {})
        hostname = asset.get('hostname', '')
        asset_ip = asset.get('ip', '')
        
        # Get enriched indicators data
        enriched_indicators = soar_result.get('enriched_indicators', {})
        
        # Process IPv4 indicators
        for ip in soar_result.get('indicators', {}).get('ipv4', []):
            is_allowlisted = any(
                result.get('indicator') == ip and result.get('is_allowlisted', False)
                for result in allowlist_check.get('results', [])
            )
            
            # Get TI enrichment data for this IP
            risk_data = self._get_indicator_risk_data(ip, enriched_indicators.get('ipv4', []))
            
            indicators.append(Indicator(
                type="ipv4",
                value=ip,
                allowlisted=is_allowlisted,
                hostname=hostname,
                ip=asset_ip,
                risk=risk_data
            ))
        
        # Process domain indicators
        for domain in soar_result.get('indicators', {}).get('domains', []):
            is_allowlisted = any(
                result.get('indicator') == domain and result.get('is_allowlisted', False)
                for result in allowlist_check.get('results', [])
            )
            
            # Get TI enrichment data for this domain
            risk_data = self._get_indicator_risk_data(domain, enriched_indicators.get('domains', []))
            
            indicators.append(Indicator(
                type="domain",
                value=domain,
                allowlisted=is_allowlisted,
                hostname=hostname,
                ip=asset_ip,
                risk=risk_data
            ))
        
        # Process URL indicators
        for url in soar_result.get('indicators', {}).get('urls', []):
            is_allowlisted = any(
                result.get('indicator') == url and result.get('is_allowlisted', False)
                for result in allowlist_check.get('results', [])
            )
            
            # Get TI enrichment data for this URL
            risk_data = self._get_indicator_risk_data(url, enriched_indicators.get('urls', []))
            
            indicators.append(Indicator(
                type="url",
                value=url,
                allowlisted=is_allowlisted,
                hostname=hostname,
                ip=asset_ip,
                risk=risk_data
            ))
        
        # Process SHA256 indicators
        for sha256 in soar_result.get('indicators', {}).get('sha256', []):
            is_allowlisted = any(
                result.get('indicator') == sha256 and result.get('is_allowlisted', False)
                for result in allowlist_check.get('results', [])
            )
            
            # Get TI enrichment data for this SHA256
            risk_data = self._get_indicator_risk_data(sha256, enriched_indicators.get('sha256', []))
            
            indicators.append(Indicator(
                type="sha256",
                value=sha256,
                allowlisted=is_allowlisted,
                hostname=hostname,
                ip=asset_ip,
                risk=risk_data
            ))
        
        return indicators
    
    def _get_indicator_risk_data(self, indicator_value: str, enriched_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract risk data from TI enrichment for a specific indicator"""
        risk_data = {}
        
        # Find matching enriched data for this indicator
        for enriched in enriched_data:
            if enriched.get('indicator') == indicator_value:
                # Extract relevant risk information
                if enriched.get('reputation'):
                    risk_data['reputation'] = enriched['reputation']
                if enriched.get('classification'):
                    risk_data['classification'] = enriched['classification']
                if enriched.get('risk_score') is not None:
                    risk_data['score'] = enriched['risk_score']
                if enriched.get('confidence') is not None:
                    risk_data['confidence'] = enriched['confidence']
                if enriched.get('threat_name'):
                    risk_data['threat_name'] = enriched['threat_name']
                if enriched.get('categories'):
                    risk_data['categories'] = enriched['categories']
                if enriched.get('sightings') is not None:
                    risk_data['sightings'] = enriched['sightings']
                break
        
        return risk_data
    
    def _create_timeline_entries(self, soar_result: Dict[str, Any]) -> List[TimelineEntry]:
        """Create timeline entries for the incident"""
        timeline = []
        current_time = datetime.now().isoformat()
        
        # Ingest stage
        timeline.append(TimelineEntry(
            stage="ingest",
            bucket=self._get_severity_bucket(soar_result.get('risk_score', 50)),
            tags=soar_result.get('tags', []) + [soar_result.get('alert_type', '').lower()],
            result="processed",
            ts=current_time,
            details=f"Alert {soar_result.get('alert_id')} ingested from {soar_result.get('source')}"
        ))
        
        # Enrich stage
        timeline.append(TimelineEntry(
            stage="enrich",
            bucket=self._get_severity_bucket(soar_result.get('risk_score', 50)),
            tags=["ti-enrichment"],
            result="enriched",
            ts=current_time,
            details="Threat intelligence enrichment completed"
        ))
        
        # Triage stage
        severity = soar_result.get('risk_score', 50)
        bucket = self._get_severity_bucket(severity)
        
        timeline.append(TimelineEntry(
            stage="triage",
            bucket=bucket,
            tags=["risk-assessment"],
            result="triaged",
            ts=current_time,
            details=f"Risk score: {severity}, Investigation required: {soar_result.get('investigation_required', False)}"
        ))
        
        # Respond stage
        if soar_result.get('investigation_required', False):
            timeline.append(TimelineEntry(
                stage="respond",
                bucket=bucket,
                tags=["investigation"],
                result="escalated",
                ts=current_time,
                details="Alert escalated for investigation"
            ))
        
        return timeline
    
    def _create_actions(self, soar_result: Dict[str, Any], 
                       device_id: str, should_isolate: bool) -> List[Action]:
        """Create actions list for the incident"""
        actions = []
        current_time = datetime.now().isoformat()
        
        # Create timeline for actions
        timeline = self._create_timeline_entries(soar_result)
        
        # Add isolation action if needed
        if should_isolate and device_id:
            severity = soar_result.get('risk_score', 50)
            isolation_timeline = timeline.copy()
            isolation_timeline.append(TimelineEntry(
                stage="respond",
                bucket=self._get_severity_bucket(severity),
                tags=["isolation"],
                result="isolated",
                ts=current_time,
                details=f"Device {device_id} isolated due to high severity"
            ))
            
            actions.append(Action(
                type="isolate",
                target=f"device:{device_id}",
                timeline=isolation_timeline
            ))
        
        return actions
    
    def generate_incident_json(self, soar_result: Dict[str, Any]) -> str:
        """Generate complete incident JSON file"""
        
        # Use incident ID from SOAR result
        incident_id = soar_result.get('incident_id', 'inc-unknown')
        
        # Create indicators
        indicators = self._create_indicators(soar_result, soar_result.get('allowlist_check', {}))
        
        # Create triage information
        severity = soar_result.get('risk_score', 50)
        tags = soar_result.get('tags', [])
        suppressed = not soar_result.get('investigation_required', True)
        
        triage = {
            "severity": severity,
            "tags": tags,
            "suppressed": suppressed
        }
        
        # Create MITRE information
        mitre_techniques = soar_result.get('mitre_mapping', {}).get('techniques', [])
        mitre = {
            "techniques": mitre_techniques
        }
        
        # Determine if device should be isolated
        device_id = soar_result.get('asset', {}).get('device_id', '')
        allowlisted = any(ind.allowlisted for ind in indicators)
        should_isolate = (severity >= 70 and device_id and not allowlisted)
        
        # Create actions
        actions = self._create_actions(soar_result, device_id, should_isolate)
        
        # Create complete incident data
        incident_data = IncidentData(
            incident_id=incident_id,
            source_alert=soar_result,
            asset=soar_result.get('asset', {}),
            indicators=indicators,
            triage=triage,
            mitre=mitre,
            actions=actions
        )
        
        # Convert to dictionary for JSON serialization
        incident_dict = asdict(incident_data)
        
        # Save to file using incident ID from result
        filename = f"{incident_id}.json"
        filepath = os.path.join(self.incidents_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(incident_dict, f, indent=2, default=str)
            
            logger.info(f"Incident JSON saved to {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Error saving incident JSON: {e}")
            raise
    
    def generate_batch_incidents(self, soar_results: List[Dict[str, Any]]) -> List[str]:
        """Generate incident JSON files for multiple results"""
        
        generated_files = []
        
        for soar_result in soar_results:
            try:
                filepath = self.generate_incident_json(soar_result)
                generated_files.append(filepath)
            except Exception as e:
                logger.error(f"Error generating incident for {soar_result.get('alert_id', 'unknown')}: {e}")
        
        logger.info(f"Generated {len(generated_files)} incident JSON files")
        return generated_files
    
    def _get_severity_bucket(self, risk_score: int) -> str:
        """Get severity bucket according to requirements: 0=Suppressed, 1–39 Low, 40–69 Medium, 70–89 High, 90–100 Critical"""
        if risk_score == 0:
            return "Suppressed"
        elif 1 <= risk_score <= 39:
            return "Low"
        elif 40 <= risk_score <= 69:
            return "Medium"
        elif 70 <= risk_score <= 89:
            return "High"
        elif 90 <= risk_score <= 100:
            return "Critical"
        else:
            return "Unknown"

